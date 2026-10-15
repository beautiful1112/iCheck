# iCheck — AI-Native IT Operations Agent Platform

## AI-led alert investigation and conversational diagnosis — 14 October 2026

An alert and an operator's question are two entry points into the same bounded
investigation engine. The user supplies intent and standing permission, not
per-device tool wiring or a mandatory workflow. AI selects relevant installed
tools, consults public references when needed, adapts to evidence, and escalates
missing capabilities into a saved Studio brief. Installation and infrastructure
changes require their existing explicit approval. Fixed workflows and Skills
remain reusable building blocks, not prerequisites for troubleshooting.

The new source implementation provides an off-by-default Automatic investigation
settings page, scoped alert admission/grouping/budgets, backend-enforced diagnostic
mode, capability discovery/requests, linked read-only follow-up runs and Skill
brief handoff. These changes are deployed in r19.25 with a healthy dispatcher and
an explicitly disabled default policy. The user confirmed that silence/closure
must stop automatic investigation. The runtime now gates execution against local
closure and native Alertmanager silence status, preserving evidence and never
automatically restarting a stopped episode when its silence expires.
Acknowledgement alone does not stop investigation. In-flight calls may finish.
Unattended remediation, remote Alertmanager federation and automatic nested
workflow execution are not implied.

The dashboard page now has direct plain-language AI creation and per-dashboard
AI revision in the running GUI. Saved conversations, proposal preview and explicit apply
remain together; manual definition editing is optional under Advanced. This
reuses native Grafana tools and the existing agent runtime, with no model call
on navigation and no automatic apply.
See [runtime contract](docs/agent-runtime.md) and [development plan](docs/development-plan.md).

## Internet research configuration — r19.24 deployed 14 October 2026

Research is a shared, replaceable platform capability, not a per-device setting
and not an assumed property of an AI model. The dedicated **AI Settings →
Internet search** page (`/settings/ai/research`) configures one Brave Search or
SearXNG connection for the selected workspace. Brave keys are write-only and
encrypted under existing server key custody. Users can enable/disable searches,
set a daily request limit and explicitly test one public query. Saving never
contacts a provider or device; a connection test may consume a search credit.
The page does not require users to edit files, register a separate MCP server,
or repeat setup for devices and workflows.

AI Operator and Studio share the connection, source-evidence contract and atomic
daily admission limit. Search results and fetched pages remain untrusted evidence;
they confer no deployment/device authority. Existing write approvals remain in
force. Automatic searching is not a claim that the full research → monitoring
extension → dashboard change workflow is complete.

This page, supporting API and additive migration `y2e4g6i8k0m3` are deployed in
r19.24. Authenticated desktop/mobile GUI and API checks passed; existing keys,
accounts, devices and monitoring settings were preserved. Search remains
unconfigured until the operator supplies a key or endpoint in the GUI. No paid
search/model call or lab probe was made for this deployment.
See [setup and limits](docs/ai-provider-configuration.md)
and [remaining workflow work](docs/development-plan.md).

## Current product direction as of 13 October 2026

The approved native server now runs r19.14 with paired SQL/GUI, a protected native
Grafana connection, SNMP generator/local installer and Prometheus/Alertmanager
rule integration. Studio and the supporting rule UI passed actual authenticated
checks. Bounded live workflow authoring/publication and Grafana dashboard
creation/revision/reviewed application passed. Saved time-range intent remains
incomplete; extension model journeys, the user's lab and notification delivery
remain unqualified. See the
deployment receipt (private development evidence; not distributed).
Approved HTTP/Linux/container/VMware gateway profiles are now provisioned in the
existing LAB subnets. Existing SNMP/Windows profiles, accounts and credentials are
preserved. Linux/container/VMware Collector metric-test capabilities are deployed
and advertised by the online LAB worker. Representative target journeys remain
unqualified; opening a page or configuring permission does not poll a device.

The 13 October product clarification makes executable extension authoring a
required Studio journey. A user can request a Netmiko-backed MCP server for
interface checks and configuration backups, review generated implementation and
tools, test it, and install/register it in iCheck. Revision and rollback also
happen through conversation. Existing MCP tool-contract generation and external
server registration only provide part of that lifecycle. Deployed Studio generates
versioned executable Netmiko packages and tests their generated Python in the
existing kernel sandbox; Studio exposes this task and conversational revision.
The runtime includes a bounded native MCP subprocess, private package installation,
encrypted backup custody and authorized human downloads. Real Netmiko transport
was exercised against a loopback SSH simulator. Managed tests, current credential
resolution, registration in the existing Tool Registry, model/executor integration,
disablement and rollback have deployed implementations and Studio controls.
Rendered fixture checks, native provisioning, additive SQL migrations and paired
deployment passed. Installed startup discovery and generated-code sandboxing
also passed under the application UID. Simulated device responses do not qualify
a lab target; real model/device acceptance remains. Local
adapters remain valid plugins. See [the extension contract](docs/tool-skill-designer.md).

Native SSH registration is separate from Collector verification: an engineer can
register a new target or add SSH to existing inventory using a protected managed
credential, then test the exact tool and host key in Studio. Registration alone
must never connect, claim healthy monitoring or queue a Collector probe.

The existing LangGraph reasoner now retains bounded earlier tool observations
across iterations, restricted to the current investigation and allowed tools.
Historical observations remain untrusted evidence, not instructions or proof of
current health. Exact metric names precede substring matches in Grafana discovery.
Workflow authoring includes conditional node-shape guidance; invalid output still
fails validation rather than being silently repaired. These r19.11 changes retain
the existing runtime, registry, durable state, duplicate-call guards and budgets.

Live r19.11 authoring still failed on a missing non-terminal success transition.
The r19.12 follow-up encodes node-specific requirements in the provider-facing
schema as well as retaining local validation. It passes 30 focused checks and is
deployed with installed-schema, sign-in and read-only API verification. The
separately approved r19.12 rerun then validated and published two versions of a
manual stored-inventory review workflow through Studio. Version 2 is current and
version 1 is retained; neither was executed or scheduled. This is live authoring
and publication evidence, not proof of a diagnostic result.

That rerun's Grafana agent discovered the connection and actual `up` metric, but
confused Grafana's datasource UID with iCheck's metric backend ID when querying.
The query failed and the run was cancelled under the agreed stop condition; no
new proposal or dashboard was applied. Deployed r19.13 exposes
registered backend discovery through the existing permission-scoped Tool Registry
and bounded sample queries through Grafana's selected datasource. The latter
requires global workspace access to the acknowledged shared dataset; generic
metric queries retain namespace/device restrictions. Native self-metrics remain
unlabeled and are not made visible by weakening those restrictions. Sixty-three
focused checks pass, including discovery/query/proposal loops and authorization.
The backed-up backend-only deployment preserved GUI, SQL, credentials and
monitoring configuration; the native query returned actual platform samples and
their source timestamps. A separately approved two-run Studio demo then created
and revised one real platform dashboard, with both reviewed proposals applied.
All ten tool calls succeeded; 43,644 tokens were reported. Native Grafana renders
four platform-only panels, including stored-sample age. The original version is
retained and a matching rollback preview is available, not applied. The AI omitted
the requested saved time range; the current handoff URL selects one hour while
the saved default remains six. Deployed r19.14 advertises native time/refresh
and preservation guidance in the existing tool schema, checks field shapes and
shows omitted versus explicit settings in the human review. Focused source tests
cover apply/restore preservation and guarded catalog upgrade. The live schema,
authenticated review page and sign-in/API checks passed; a future model
request is not yet qualified. Do not treat proposal validation as complete intent
fulfillment. This demo did not probe, enroll or change any lab device.

A categorized **Monitoring** page now brings together configured device and
service connections, including disabled, pending and failed targets. Deployed r19.7
provides scoped categories/search/pagination, collection observations,
device-alert counts and target/Studio/Grafana links. Requested measurement
freshness is checked on demand against existing Prometheus samples; scrape
success alone is not full measurement proof. The **Alertmanager** management section
is deployed with readiness, active notifications,
sanitized receivers/routes, reviewed exact-rule silences and inbox delivery history.
It reuses the native service, metric-rule page and existing audit log. Authenticated
live readiness/configuration checks and an isolated native silence flow passed.
Receiver editing remains protected native configuration.
Monitored service endpoints do not revive retired Service Intelligence.
The [current plan](docs/development-plan.md) records these missing deliverables
and distinguishes deployed foundations from completed engineer journeys.

The device's continuous-collection approval follows its tested monitoring
template. Exporter collector names and VMware/container scope come from that
template and cannot be edited into a different measurement set in the approval
form. Engineers change measurements in Studio and retest. Native gateway profile
defaults are shared between Studio and Assets, including Windows; existing
enrollment profiles are retained. Internal names and timeout/expiry options stay
under Advanced, while measurements and collection interval remain visible.

Device verification is separate from routine collection and live metric health.
The deployed update defaults to SNMP without requiring ping, reports Collector method
availability, and lets the engineer disable or re-enable a connection with a clear
confirmation. Disabling retains history and withdraws authority; enabling needs
fresh verification and a new collection approval. Transport-only port checks do
not satisfy a requested exporter measurement test. No kernel permission or lab
probe is added by merely exposing these controls.

iCheck is an AI-native monitoring management, operations and troubleshooting
agent for network, system and DevOps engineers. Prometheus collects and stores
time-series metrics through exporters/adapters; Grafana displays all monitoring
metrics. iCheck owns conversation, reusable capabilities, configuration,
inventory, alerts, evidence and approved actions, not another charting framework.

Keep AI Operator, redesign Capability Studio as a conversation-first builder,
and remove Services and Service Intelligence from the product UI. IP/MAC and
Wi-Fi terminal histories remain durable PostgreSQL inventory on supporting pages.
All modules use replaceable plugin contracts; native adapters do not need to be
separate MCP servers. Users create and improve collectors, dashboards, Skills
and workflows inside iCheck, with validation and confirmation before activation.

The immediate delivery order is Grafana deployment → AI Grafana management and
simple Studio → complete SNMP/HTTP monitoring creation → Linux/Windows,
containers and VMware → alert/investigation handoff. Use native Grafana HTTP
tools and authenticated dashboard links first. The integration design defines
deployment, resource ownership, plugin contracts and acceptance:

- [Replacement development goal](docs/codex-goal.md)
- [Grafana monitoring integration](docs/grafana-monitoring-design.md)
- [Current delivery plan](docs/development-plan.md)

These decisions supersede earlier custom metric visualization, Service
Intelligence and production-before-preview priorities in this document. Dated
implementation records remain historical evidence. Native Grafana and full-page
Operator/device links are deployed. Its eleven native AI tools, protected
connection settings and single-confirmation proposal/revision/rollback UI are
implemented and staged as r18, pending approved cutover and live AI acceptance.
The running application remains r17 with the Grafana-linked GUI. Newer source
implements the task-facing Studio/library and retires Service/Situation/custom
metric-chart UI journeys, retaining their backend records. It adds a scoped
inventory/alert-only Operator summary and a read/propose-only dashboard task.
These changes need a paired backend/GUI package beyond the frozen r18 candidate.
Complete monitoring activation, fresh sample proof and live AI acceptance remain
required; a saved or fixture-validated template is not enabled monitoring.

The HTTP/API source now has a declarative numeric mapping/probe adapter and device
configuration/test controls. It uses existing encrypted credentials, scoped worker
leases, revision-bound monitoring approval and gateway discovery/scraping. A
temporary Prometheus stored fresh fixture metrics, with real HTTP/TLS tests;
no running target, job or credential changed. [HTTP monitoring](docs/http-monitoring.md)
records the contract and limits. Studio now uses the same immutable contract for
conversation, selected-target testing, one reviewed publish/enroll action, fresh
sample checks and retained native Grafana proposals. History restores a prior
definition as a new version. The source/private-fixture journey is verified;
live model/device/Grafana acceptance and a coordinated approved cutover are still
required before presenting it as the running product.

The SNMP source now has real standard-network and Cisco CPU symbolic profiles,
native MIB dependency compilation and strict exporter parser validation. A
confirmed module transaction preserves existing modules, installs immutable
versions and rejects stale catalog previews. Real standard/vendor MIBs passed
in private catalogs, without contacting a lab device. The source now connects
that compiler/installer to Studio conversation and the shared selected-target
test/enroll/fresh-Prometheus/Grafana journey. A bounded local Unix-socket broker
handles only reviewed module-catalog installation; AI cannot approve the write.
Real loopback SNMP and temporary native Prometheus tests passed. Protected broker
and runtime provisioning, a coordinated release and live engineer acceptance
remain required; no running release or device approval was changed.
See [SNMP generation](docs/snmp-exporter-attestation.md).

## Linux and Windows exporter monitoring

Linux/Windows monitoring source now extends the same declarative template
contract instead of adding another designer or chart renderer. The existing
worker/gateway verifies requested metric names, types and collector results;
fresh Prometheus evidence gates native Grafana proposals. Real Linux host
measurements passed an isolated native exporter/Prometheus path. Windows has
fixture and lifecycle checks but still needs a real host. Deployment, live model
authoring, live Windows/WinRM/container/vSphere qualification and metric notifications
remain separate requirements. See [system exporter monitoring](docs/system-exporter-monitoring.md).

The native CIM request/read Agent tools already use the governed on-demand
Collector and fixed operation templates. Their source now validates observation
freshness and current device/assignment, correlates a read to the requested
deployment/time and preserves complete operation coverage in bounded results.
Human request approval and retained history remain unchanged. Fixtures exercise
the transport and evidence path; they do not qualify a real Windows host.

## Container exporter monitoring

The cAdvisor container source plugin now extends the same monitoring-template
contract and Studio journey. It reads only the approved host endpoint, filters
labels, preserves source timestamps and requires all requested measurements per
matching runtime-container ID before declaring fresh collection. Grafana owns
the saved dashboards, including CPU cores and measured memory/age panels.
Private fixture Prometheus verified the adapter path; no actual container runtime
or live application was changed. See [container monitoring](docs/container-monitoring.md).

## VMware exporter monitoring

The VMware source plugin uses a preconfigured protected exporter endpoint and
platform-owned exact object selection. Hosts, VMs and datastores reuse Studio
authoring, selected-target metric testing, reviewed enrollment and native Grafana
proposals. Metadata filtering and complete selected-object/partition evidence
prevent availability-only success. Upstream performance timestamps are unavailable;
fresh Prometheus receipt is not object health. Source/private-fixture checks pass,
but deployment and real vSphere qualification remain required. See
[VMware monitoring](docs/vmware-monitoring.md).

## Native metric alerts

Threshold rules use the existing approved monitoring enrollment and declared
measurements. iCheck tests fresh samples, prepares a retained native rule preview
and requires exact human confirmation before a guarded catalog replacement and
verified Prometheus reload. Prometheus remains the only metric evaluator;
Alertmanager delivers to the existing iCheck inbox. SQL retains rule history and
episodes, not another time-series store. Native AI tools can discover targets,
prepare a preview and inspect its receipt, but cannot enable it. Alerts link to
the saved source-specific Grafana dashboard and a draft AI investigation.
Withdrawal and prior-definition restore retain history. Acknowledgement and
condition clearance never establish infrastructure recovery. Source/private
native engine and PostgreSQL checks passed; running-server provisioning and live
controlled-fault acceptance remain pending. See [metric alerts](docs/metric-alerts.md).

## Reusable checks in Studio

Workflow and diagnostic Skill templates share conversation authoring, immutable
versions, explicit publication and the existing bounded runtime. Saved checks now
have ordinary input controls and authorized device choices on the Operator;
complex input schemas stay under Advanced. Following a library link does not
execute a check or activate a recurring trigger. Studio restoration prepares an
earlier definition as a new revalidated draft in the same conversation, without
a model/tool call or changes to existing runs. A failed restore cannot leave an
orphan candidate or replace the current preview. Source API/graph and fixture UI
checks are distinct from live model/lab acceptance and deployment. See
[workflow templates](docs/workflow-templates.md).

## Supporting Assets workspace (v0.1 r17)

The operational Assets entry is inventory-first, grouped by managed device type
with current collection state. Enrollment is a secondary route. Device context
separates live evidence, published-template assignment and configuration. Template
assignment is the approved binding of a published capability, not a raw exporter
module-name field. Non-deployable AI drafts must never appear as applied templates.
Availability comes from scoped fresh telemetry and current approved identity,
not a successful historical onboarding check. The unified conversational SNMP
module generation, installation and automatic revision lifecycle remains a separate
uncompleted milestone; an inventory UI change is not evidence that it exists.

## Validated SNMP configuration and observed inventory identity (v0.1 r16)

AI Tool permissions and exporter modules are separate typed concepts. Enrollment
and monitoring validate installed module names; the GUI can correct an existing
connection without reenrollment, preserving its target and credential scope.
SNMP verification is a bounded identity operation, not a full telemetry walk.
Managed SNMP uses four fixed scalar GETs; continuous interface collection remains
an independently authorized `if_mib` operation. Current leased observations bind
sysName to the device target/revision, retain it durably and expose it to inventory
display/search without replacing an operator alias. Unknown errors remain unknown;
recognized exporter constraints carry safe root causes and actionable repair controls.
Configuration correction invalidates stale collection approval. It never widens
network custody or silently repairs every unrelated device.

## Optional placement and explicit-request onboarding (v0.1 r15)

Physical location is optional structured metadata: zone → building → floor → room
→ rack → height (rack U position). Missing values remain NULL, not an invented
default Site. Credential/Collector authorization stays in exact worker selectors;
blank location must not remove their scope or network bounds. Legacy Site values
remain compatible; editing descriptive placement does not retarget collectors.

A narrow explicit Add/Enroll request authorizes only its finite IP list and saved
profile. The built-in deterministic LangGraph enrollment flow binds that original
human intent, validates it, commits inventory/monitoring intent and an owned Tool
receipt atomically, then returns IDs and an inventory link. No external inference
is needed for this fast path. Ambiguous or preview requests retain the normal
Agent/approval flow. Skills and scheduled workflows cannot inherit its consent.
Completed enrollment requires the durable receipt; live monitoring still requires
Collector verification and current native gateway custody. Managed SNMP receives
finite 30s/10s/seven-day monitoring intent using existing `preview-snmp` custody;
no CIDR, credential, remote-device configuration or privileged host change is
authorized by merely saying Add. See [onboarding contract](docs/device-onboarding.md).

## Operator-owned runtime timeouts and staged onboarding (v0.1 r14)

The operator can independently edit each provider's bounded model-attempt timeout
through the GUI, without re-entering credentials or rebinding routes. Human/CSRF,
current-timeout and managed-revision checks protect exact intent. New guided
external-reasoning connections use a 120s default; existing values are changed only
through an explicit authorized update. Task budgets, lease/output bounds and
device approval remain independent. Saving operational metadata does not infer.
Device onboarding Tools are real embedded control-plane services, while SNMP I/O
is performed by the scoped Collector only after approved enrollment. The current
conversation uses the general LangGraph kernel; it is not a dedicated pre-bound
fixed SNMP template. Prompt guidance documents credential discovery, exact preview,
human approval and deferred protocol preflight. Fixed templates may reduce model
turn overhead but must be authored/published/bound as actual governed artifacts,
not inferred from a documented sequence or bypassed through a chatbot write.

## Bounded runtime correction (v0.1 r13)

The Worker, control plane and model adapter share the persisted investigation
deadline. Reasoning renews ownership first, keeps model I/O inside provider,
investigation and lease budgets, and permits only a small bounded return margin.
Provider keep-alives must not extend total attempt duration. Interactive Qwen
uses conservative output limits and explicitly enabled minimal reasoning for
the affected mandatory-reasoning model. Runtime policy does not alter secrets,
model identities, route budgets, device permissions or approval requirements.
Invalid Agent output retains safe schema paths/rule codes rather than untrusted
raw model prose. Diagnosis correlates retained failure and quota receipts, exposes
late usage/unresolved charges and labels irrecoverable legacy detail honestly.
Regression acceptance covers remote Worker execution, timeout/body keep-alives,
local validation/redaction, known/unknown accounting and GUI rendering. Deployment
is an operator-authorized native upgrade, not autonomous privileged self-patching.

## Provider validation evidence and mandatory reasoning (v0.1 r12.1)

Provider failures retain bounded, allowlisted error types, codes, parameter names
and fixed validation constraints. Raw upstream bodies, prompts, credentials and
arbitrary values never enter UI/audit/Agent evidence. Unknown constraints remain
explicitly unknown; historical discarded details are not reconstructed as facts.
Readiness consumes per-model reasoning metadata rather than equating parameter
support with an ability to disable reasoning. Mandatory reasoning stays enabled;
the test selects the lowest explicitly allowed effort, retains its output cap,
charge approval, quota accounting and full local decision/Tool validation. Qwen
probe and Agent schema formats align, without silently changing model routes or
budgets. Diagnosis never authorizes a paid retry or privileged self-modification.

## AI-native self-iteration and module lifecycle update (v0.1 r10)

The first in-product repair loop is evidence → diagnosis → proposed model/route
change → opt-in bounded inference/schema test → human approval → fresh scoped
retry. It works even when the configured model is unavailable, because retained
failure diagnosis is deterministic and requires no second inference call.
Batch/synchronous mismatch and sanitized provider authentication, credit, policy,
parameter, endpoint and rate errors are supported; missing evidence is explicitly
unknown, not an invented network/device diagnosis. No arbitrary root-process
code patching, self-deployment or silent policy weakening is authorized.

Credential references, providers, model profiles and purpose routes are separately
managed modules. Each has self-service dependency preview and approved retirement/
restoration. Active dependencies and investigation pins block removal; identities
and historical runs are preserved. Multiple enabled profiles form choices used
by primary/ordered-fallback purpose routes, not unbounded parallel calls. Approved
model switching moves only selected routes and retains previous model identity.
The advanced GUI explains the four configuration layers and their prerequisites.
Existing plug-in/Skill/workflow authoring remains subject to validation and
publication, not privileged trusted-runtime self-modification.

## AI-native credential and enrollment design update (r9)

Device onboarding is a native Agent Tool workflow: discover eligible credential
metadata, prepare an explicit device-IP plan, obtain human approval, verify through
the site Collector, preview a published collection policy, and approve activation.
The model cannot resolve device secrets or activate a preview itself. GUI proposal
cards are the human control surface, not a separate developer/CLI onboarding path.

Write-only managed credentials cover SNMPv2c, Windows/WMI over WinRM HTTPS, HTTPS
API tokens, and SSH passwords/private keys. Ciphertext custody is namespace-local
with a separately backed-up server key. External Vault references remain pluggable.
Credential selection must affect real adapter authentication, including SNMP
Exporter and the continuous gateway. Allowlists, SSH host trust, TLS validation,
published collectors and finite monitoring approvals remain independent controls.
An approved plan is not evidence of successful collection. Live lab acceptance
and high-volume performance measurements remain separate from release testing.

## Engineering Preview v0.1 release scope

The current deliverable is a native, single-node engineering preview. The AI
operator remains the kernel; generic collectors, governed Skills/workflows and
in-product authoring remain plug-in contracts. Inventory belongs on subpages,
including a dedicated collected-interface view and bounded retained IP/MAC and
Wi-Fi history. Default infrastructure operations remain read-only, with pluggable
external credential references or write-only encrypted managed device credentials,
never plaintext secrets in SQL. The guided
OpenRouter adapter additionally accepts a write-only key through the Web GUI,
stores only AES-256-GCM ciphertext in namespace-scoped SQL, and keeps its encryption
key separately on the server. Exact provider-bound outbound approval, authenticated
health/model discovery and atomic model/route setup are part of that flow;
collectors and remote Agents never receive the key. See
[AI provider configuration](docs/ai-provider-configuration.md).

The dedicated alert evidence page exposes retained source episodes, status
filters, acknowledgement and supported inventory-event rule creation. Rules
affect the current namespace, so creation requires global `alerts.admin`.
Acknowledgement requires `alerts.manage` and access to the specific episode;
it does not resolve the underlying fault. Generic inventory rules are not
arbitrary Prometheus threshold jobs.

The user will onboard their EVE-NG SNMP, Linux and Windows devices through the
running Web GUI and perform lab acceptance themselves. Do not populate that lab
on their behalf. Ship coherent source, native installation guidance, GUI quick
start and repeatable read-only smoke/demo tools. Production fleet qualification,
HA and advanced OAuth recovery are later scope, not silent preview release gates.
See [preview installation](docs/engineering-preview-installation.md) and
[current release plan](docs/development-plan.md). Qualification history below
retains its original full-product scope.

Latest recorded application deployment: v0.1 r19.25 paired GUI/backend (private development evidence; not distributed),
including direct Dashboard AI and default-off alert investigation. The earlier
r2 qualification (private development evidence; not distributed),
[r51 / installed r30 checkpoint](docs/native-release.md)
and [release-readiness audit](docs/release-readiness-audit-2026-10-05.md) retain
their full-product scope. Historical milestones below are not preview acceptance.

The latest durable local family qualification (private development evidence; not distributed)
retains the exact private plan and reviewed issuer proof, then commits a fresh
current-human admission before each provider mutation. All locks are released
before I/O. Owned operation receipts survive later permission withdrawal and
remain immutable. Completion records the exact family containment time without
rewriting an unknown issuer outcome or changing another live generation.

Guarded local start/read/execute APIs expose token-free history. A contained new
attempt no longer blocks older-family recovery, but local completion does not
clear server revocation state, discard old-family uncertainty or permit reconnect.
Conditional server adoption and stale-plan replacement remain separate work.
Source head is `o2s4u6w8y0b3`; 96 distinct focused source and 13 native PostgreSQL
cases pass with synthetic upstreams. Actual governed Tool execution, recovery
UI, complete process-loss/live-provider acceptance, coherent packaging and every
original production/lab gate remain. No installed change or demo is included.

The preceding local Vault provider qualification (private development evidence; not distributed)
adds private exact-version plans and token-free operation receipts. Pending
consent recovery preserves its original credential family. Historical recovery
retires only verified affected versions and never restores an older family or
replaces another live generation. Ordinary credential readers reject a local
reservation. Execution requires fresh authority and durable-receipt hooks before
proceeding to each mutation; ambiguous responses need exact owned readback.

That provider-only phase did not add database persistence, current-human
adapters or guarded APIs; the durable integration above now supplies them.
The provider module does not itself validate issuer proof or change control-plane
status. Its qualification used source head `n1r3u5w7y9a2` with no installed
change or integrated demo. Conditional reconnect remains separate work.

The preceding exact transaction recovery qualification (private development evidence; not distributed)
adds a secret-free original transaction ID, state digest and public PKCE challenge.
Recovery claims an unresolved or historical attempt and pins existing published
containment/verifier capabilities on separate MCP servers. Eleven typed bindings
identify the original issuer/client/resource/generation/version and transaction.
An approved write and fresh independent evidence must prove revoked family,
blocked issuance and exclusive transaction scope. Shared or ambiguous families
remain fenced rather than receiving a broad client-wide revocation.

A different currently authorized human retains `issuer_verified` evidence.
This does not authorize local Vault cleanup, reconnect or re-execution of an
unknown write. A claimed late callback retains compensation or its exact owned
storage receipt without publishing it as connected. Historical proof leaves
another current generation's slot untouched. Older history needs its matching
retained transaction and authenticated PKCE ciphertext; missing evidence is
not reconstructed from a time window or current configuration.

Source head is `n1r3u5w7y9a2`. Twenty-five new source/schema checks, 57 existing
regressions and ten actual private PostgreSQL cases pass. Issuer/Vault data and
retained containment/verifier calls are synthetic. Local cleanup, operational
workflow launch/pin replacement, actual Tool execution, administration UI,
live cross-store truth, coherent packaging and every original production/lab
gate remain. No integrated demo or installed changes are authorized by this phase.

The preceding consent custody qualification (private development evidence; not distributed)
adds an original configuration/authority snapshot and durable generation attempt
before code redemption. The server is fenced and locks are released before
mutation I/O. Publication uses the pre-redemption Vault target; a later change
cannot silently rebase it. Only known unstored tokens receive compensation,
and acknowledgement does not prove family containment. Unknown attempts stay
fenced; an old-generation cleanup proof cannot clear them.

Generation history preserves original targets and owned storage receipts without
tokens, even after transaction expiry. Its bounded API omits private snapshots
and Vault paths. Superseded/local-revoked status is not independent proof about
every remote family. That phase's source head is `m0q2t4v6x8z1`; 106 distinct focused source
and ten PostgreSQL cases pass. One actual private-child SIGKILL covers a synthetic
mint window, not live issuer/Vault or complete recovery. Independent new-family
and historical-family recovery, Tool scope/integration, normal administration
UI, coherent packaging and every original production/lab gate remain.

The preceding human authority qualification (private development evidence; not distributed)
requires current credentials, enabled identity and namespace, selected-region
grants and global scope at each recovery decision. Authority rows stay locked
through admission commit, not external mutation I/O. Expiry is checked after
waits. Withdrawal blocks the next admission but does not discard the verified
receipt of an already-authorized fence or deletion. Sixty-five focused source
checks and 12 distinct actual PostgreSQL cases pass, including observed server,
role and token lock waits. This is source qualification, not live-provider,
normal recovery GUI or complete product acceptance.

The preceding OAuth recovery source (private development evidence; not distributed)
adds durable custody at `l9p1s3u5w7y0`, beyond frozen r51. Recovery first fences
the server, then requires an approved containment Tool and a separately pinned,
read-only verifier to prove the exact issuer/client/resource/consent generation
and Vault version. A different authenticated human reviews that evidence.
Verified fence ownership commits before exact-version deletion; lost responses
require matching readback, not grant replay or an operator's pasted claim.
Recovery does not resolve an unknown original action, activate a Tool, or grant
execution. Reconnection remains separate fresh consent.

New consent audits retain non-secret original-target fingerprints and Vault
identity. A missing legacy intent can be reconstructed only from that snapshot,
not the current mutable profile. Historical evidence gaps and corrupt nonempty
custody remain fenced. Fresh consent cannot erase an expired uncertain
reservation. Seventy-five distinct source checks and seven real
PostgreSQL cases pass; the two-user API uses actual bearer authentication and
non-owner RLS. Upstreams are synthetic. Consent admission/compensation/family
history, normal recovery GUI, live Tool/provider
truth, process-loss boundaries, coherent new packaging and all original full
production/lab gates remain. Installed r30 and frozen r51 are unchanged.

The r51 candidate (private development evidence; not distributed) combines
the k8 storage migration/ORM semantics and explicit active-tool wording. Its
normal packaged GUI (private development evidence; not distributed)
verifies consent, reasoned revoke and reconnect with a fresh generation and
retained Vault version. Actual SQL-null clearance permits the packaged cleanup
guard inside a rolled-back transaction without erasing generation history.
Seven candidate checks, private offline stage and frontend build/HTTP checks
pass. This selected flow creates no Tool activation or Investigation and does
not replay the earlier Worker/Agent journey. Private cleanup is complete;
installed r30 is unchanged. Explicit unknown-family/legacy-intent recovery and
remaining lifecycle/policy/full GUI/native/production/live/load/recovery/lab
gates still prevent a first release or integrated demo.

Earlier SQL-null source qualification (private development evidence; not distributed)
repairs the storage contract described below. Source head `k8n0q2s4u6w9` uses
SQL-null ORM semantics and a visibility-guarded migration that normalizes only
JSON literal null. Real and invalid non-null custody, nested nulls, unrelated
metadata and all namespaces are preserved. Seventeen distinct focused checks
pass, including eight new actual PostgreSQL cases and five affected migration
guards. Active-only call wording is clarified without altering history. Frozen
r50 and installed r30 are unchanged; a new combined candidate and packaged
qualification still precede the unchanged complete-design release/demo gates.

The r50 candidate (private development evidence; not distributed) freezes the
combined coordination, observation and cleanup source at `j7m9p1r3t5v8`.
Private offline staging and seven candidate checks pass. The
normal packaged GUI (private development evidence; not distributed)
separates consent, conversational publication, packaged attestation, reasoned
activation and bounded Agent execution. Sourced Worker receipts age naturally
without overwriting consent metadata. Normal revoke clears synthetic upstream
tokens and the exact bundle; separate deactivation preserves call history.

Cleared receipt/intent fields must be SQL NULL, not JSON literal `null`. R50
violates this storage contract, causing the actual cleanup downgrade guard to
reject cleared custody. Repair both ORM fields and introduce a guarded migration
that normalizes only JSON-null rows across all namespaces, preserving real
history and refusing incomplete RLS visibility. Qualify populated PostgreSQL and
a new combined backend before release. The active-only runtime summary also
needs an explicit label. Private fixtures are stopped and removed; installed r30
is unchanged. All original platform commitments and native/production/live/load/
accessibility/physical-lab gates remain; no integrated demo is authorized.

Earlier r48 repairs OAuth reconnect after Vault KV v2 soft deletion. Data 404 is not
proof of a new key: the exact metadata version supplies CAS; permission denial,
malformed metadata and races fail closed without retry. The control-plane Vault
identity needs read permission on that exact metadata path, not broad metadata
listing or additional Worker authority. The release record (private development evidence; not distributed)
and OAuth GUI evidence (private development evidence; not distributed) verify actual
packaged consent, revocation, denied consent and successful reconnect. OAuth
does not publish, attest, activate or execute a Tool. Twenty-nine new cases,
three affected transport cases, seven candidate checks and private offline
staging pass; the unchanged frontend and prior backend evidence are inherited.
Three focused states and real Revoke keyboard focus pass. Private runtime,
credential and database fixtures are cleaned up; inactive candidate/stage
artifacts are retained. OAuth refresh/step-up/in-flight and broader GUI/accessibility,
fresh approved native deployment, production/live/load/recovery and physical-lab
acceptance remain. Readiness is false; the integrated demo is deferred.

The later OAuth Worker qualification (private development evidence; not distributed)
and handoff readiness addendum (private development evidence; not distributed)
use unchanged frozen r48. OAuth consent does not replace publication, packaged
attestation or reasoned activation. A separately bounded Agent resolves its
Vault bundle locally and completes one exact-version read with a persisted
evidence/binding. Revocation retains the canary/registration history; current
OAuth state blocks a fresh executor before Vault/MCP I/O. The failed attempt
produces no evidence and escalates; a separate GUI deactivation then removes
authority. The fixture's subsequent reason failure and contrast incompletes
remain explicit. Three one-shots exit zero; operational fixtures are cleaned up.
This closes selected handoff/executor cases, not refresh, scope-step-up,
in-flight/live-provider behavior or broader native/production/lab acceptance.

Earlier packaged boundary: serial refresh evidence (private development evidence; not distributed)
and its readiness addendum (private development evidence; not distributed).
The same frozen r48 Attestor and Agent each rotate a naturally expired token,
using Vault versions 2 and 3 before authenticated reads. Twenty-five new and
three affected cases pass; one new concurrent invariant fails. The GUI and
database still show the original expiry after Worker-local refresh. These are
demonstrated product gaps, not completed refresh/fleet acceptance. R48 is not
rebuilt or installed; no integrated demo runs.

The refresh implementation must coordinate the exact credential across
processes **before** redeeming its grant. A post-redemption Vault CAS, process-
local mutex or scheduler-only serialization is insufficient for shared remote
Workers. Contenders need a bounded wait, current-generation revalidation and
safe reuse of a committed result. Timeout, crashed ownership and lost rotation
responses must fail closed without blindly replaying the prior refresh token.
Reconnect/revocation must fence late refresh commits; explicit uncertain-state
recovery must not silently restore authority. Public-client rotation and replay
family invalidation follow [RFC 9700 §4.14.2](https://www.rfc-editor.org/rfc/rfc9700#section-4.14.2).

The selected implementation direction is an in-bundle, exact-key Vault KV v2
CAS reservation, not a new global lock service or broader Worker policy. Store
bounded ownership/generation/state metadata with the existing credential; only
the reservation winner may redeem, then commit against its reservation version.
Contenders read/wait for a valid committed result. Unknown outcomes remain
fenced, rather than becoming replayable after a timer. Revoke/reconnect advance
the same version/generation boundary before a late owner can commit. This uses
the [documented KV v2 versioned-write CAS contract](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#createupdate-secret),
but the coordination/recovery behavior is an iCheck design, not a feature Vault
implements automatically. The source repair (private development evidence; not distributed)
now implements this reservation, bounded coalescing and durable uncertainty,
with 80 distinct focused passes including separate-process and real crash tests.
Its current addendum (private development evidence; not distributed)
distinguishes source qualification from the unchanged frozen/installed product.
Known-token compensation first acquires a new revoke fence; ambiguous commits
never trigger blind revocation of a published/newer family. Revocation deletes
only its exact reserved version and verifies the current head before success.
The control-plane needs a reviewed exact `<mount>/delete/<bundle-path>` update
policy; refresh-only Workers need no version-delete grant. No policy is applied.
All legacy
Workers that ignore reservation metadata must be drained before this contract
is enabled; synthetic version counts above describe r48, not the source repair.

Worker refresh observations carry only non-secret version/expiry metadata
over the authenticated, assignment-bound contract. Bind them to namespace,
server, credential generation/profile revision and current run; reject late,
revoked, mismatched and out-of-order observations. Distinguish authoritative
control-plane observations from Worker-reported freshness in the UI. A receipt
cannot connect OAuth, expand scope, activate a Tool or grant execution authority;
tokens must remain in local Worker/Vault custody. Merely relabeling the old
expiry does not complete this implementation or acceptance gate.

The source observation qualification (private development evidence; not distributed)
implements Provider, Attestor, HTTP-only and direct Agent receipts plus consent
transaction snapshots, locked callback and conditional generation-bound revoke.
Eighty-five distinct focused checks pass, including the authenticated product
API/lease/checkpoint handoff. Receipts are monotonic, bounded and separate from
consent expiry and authorization. Malformed metadata cannot discard an owned
unknown-write result. The GUI explicitly labels observed source/time/state and
ages receipts with its five-second clock. Legacy consent is not backfilled;
its source head `i6l8n0q2s4u7` requires explicit reconnect before worker handoff.
That record remains source qualification, not packaged browser acceptance.

The PostgreSQL custody qualification (private development evidence; not distributed)
adds 58 distinct passes, including 40 actual migrated non-owner PostgreSQL cases.
Actual server/profile lock waits recheck current consent, profile revision and
worker ONLINE/selector containment; callback pins the shared token profile
before issuer/Vault I/O. OAuth custody requires a non-autocommit READ COMMITTED
transaction, matching [PostgreSQL's updated-row behavior after a lock wait](https://www.postgresql.org/docs/16/transaction-iso.html#XACT-READ-COMMITTED).
Other transaction modes fail before external credential I/O; this does not make
Vault and PostgreSQL one atomic transaction.

Revoke commits pending status together with a strict internal cleanup intent
that pins server/namespace, consent generation, original profile/reference and
Vault identity. Retry retains that target after an expired session, profile edit
or actual process exit after commit. A disabled profile may permit this exact
cleanup, never execution. Missing/corrupt legacy intents or changed Vault identity
require administrative recovery rather than guessing a target. Completion checks
the exact pending intent and generation. Source head `j7m9p1r3t5v8` adds a nullable
internal column, not public credentials or fabricated legacy custody. Actual
populated roundtrip/RLS and retained/hidden-history downgrade guards pass.

Freeze a combined new candidate and qualify its normal packaged GUI flow next.
Cross-store uncertainty and explicit unknown-issuer/legacy-intent recovery remain:
the unknown live issuer token after the earlier actual Worker crash is fenced,
not proved revoked. Live issuer/Vault policy, legacy-Worker drain, scope-step-up/
in-flight and broader production/native/lab gates remain. The private test cluster
is stopped; frozen r48, installed r30 and the integrated-demo gate are unchanged.

These repairs do not narrow the original platform design: conversational native
creation of API/SNMP/SSH collectors, topology/views, workflows, Skills and governed
automation; bounded AI L1 loops and configurable models; alerts and persisted
IP/MAC/Wi-Fi terminal inventory; native fleet operation and normal GUI device
onboarding remain commitments. The [development plan](docs/development-plan.md)
and [full readiness audit](docs/release-readiness-audit-2026-10-05.md) retain their
unfinished native, production, live-provider, load/recovery, accessibility and
six-class physical-lab gates. Synthetic component evidence is not full-design
completion.

Earlier r47 inherits the unchanged r35 backend/runtime/operator payload. Its
release record (private development evidence; not distributed) and
execution evidence (private development evidence; not distributed) verify the
separate publication → authenticated Worker attestation → explicit activation
→ bounded Agent execution → promotion/deactivation controls. A typed Skill
performs two read-only tools and returns actual persisted citations; an exact-
allowlist Agent completes one synthetic HTTPS MCP call. Deactivation removes
the tool from the model catalog and the next run escalates without a call.
R47 repairs enabled activation contrast and real-time attestation freshness,
including submission and recovery-prompt guards. Real browser expiry disables
activation without refresh. Twenty-eight frontend cases, thirty distinct fixture
cases across corrected segments, build/typing/lint, seven bundle/host cases and
private staging pass. Failed initial fixture execution and incomplete contrast
checks remain explicit. This qualifies bounded synthetic components, not live
model quality, production custody/mTLS, physical truth or native operation.
Broader MCP/conditional GUI, fresh approved native rollout and production/live/
physical-lab acceptance remain; the integrated demo is deferred.

The earlier 10 October recovery increment (private development evidence; not distributed)
uses that unchanged frozen candidate. An actual synthetic read-only MCP failure
opens the circuit, disables the Tool and creates a critical alert/audit. The
next investigation makes no call. Fresh packaged Attestor evidence alone does
not recover authority: a separate reasoned GUI approval consumes it and returns
the Tool to a 10% canary. The circuit alert resolves while the original loss
alert and failed execution history remain. An excluded cohort run makes no
request. Thirty-two additional GUI-generated candidates were outside the cohort
and cancelled before claim; the bounded search ends without a recovered eligible
success or promotion. These remain explicit gates, not inferred completion.
Three focused rendered states and actual Re-attest/Recover keyboard focus pass;
seven new fixture cases have terminal passes across corrected segments. The
readiness addendum (private development evidence; not distributed)
inherits prior build/backend evidence without rebuilding or repeating full
suites. No native authority changes; all private fixtures are cleaned up.
Production custody, OAuth/fleet/in-flight recovery, full accessibility and the
normal GUI-onboarded physical lab remain unaccepted at that boundary.

The subsequent recovered-canary evidence (private development evidence; not distributed)
and r47 addendum (private development evidence; not distributed)
close the selected recovered 10% success/promotion gate without changing r47.
A fresh GUI-created eligible investigation completes two Agent decisions and
one exact-version MCP read with one retained evidence/binding. An excluded run
makes no call; eleven other candidates are stopped unclaimed. Separate reasoned
GUI promotion returns HTTP 200, then normal deactivation removes runtime
authority. Failed history and the original open loss alert remain, with no
closure receipt. MCP promotion states have zero automated findings; four
completed-page contrast incompletes still require manual review. No code/build/
full-suite/native mutation or demo ran; private cleanup is complete. This is a
synthetic component acceptance, not fleet, production or whole-design completion.
Broader GUI/accessibility, approved deployment, production/live/load/recovery
and normal GUI-onboarded physical-lab gates remain. Readiness stays false.

At the earlier r46 boundary, the unchanged r35 payload was inherited. The
release record (private development evidence; not distributed) and
richer-authoring evidence (private development evidence; not distributed)
verify in-product local file uploads, selected OpenAPI GET generation, bounded
fixed-SSH sample mapping, explicit publication and non-publishable MIB numeric-
OID proposals. R45 conversational refinement preserves the original published
version while creating a new unpublished draft. This uses a deterministic
loopback model, not live-model quality acceptance. The raw full OpenAPI/MIB is
not retained as model context; unrelated operations and MIB descriptions are
absent from actual model summaries and stored messages. Native chooser/editor
names and the disabled-publication governance panel now support stable naming
and actual keyboard scrolling with visible focus. Twenty-three UI regressions,
thirty-three fixture cases, build/typing/lint, seven bundle/host cases and private
staging pass. Recorded scrolled-state contrast incompletes remain limits, not
hidden failures. No SSH/device walk, collector run, attestation, activation,
native rollout or integrated demo occurred. Full-product readiness stays false;
actual MCP/Skill/Agent execution, broader GUI and approved native/live/lab gates
remain. User-authored capabilities still require separate governed activation.

At the earlier r44 boundary, the unchanged r35 payload was inherited. Its
release record (private development evidence; not distributed) and
cutover/recovery evidence (private development evidence; not distributed)
verify synthetic GUI permanent retirement, exact uncertain retry after peer
revocation, a confirmed receipt surviving metadata-response loss, reload-based
receipt recovery, real review expiry and consented historical revalidation.
Historical acceptance cannot execute another retirement. Measurements stay
unchanged; logical Situation supersession is not measured repair or reviewed
incident closure. R44 refreshes bounded public mapping summaries, adds live
expiry/identity guards and distinguishes confirmed history from an uncertain
execution intent. Twenty-five frontend regressions, thirty fixture guards,
build/typing/lint, seven bundle/host cases and private staging pass. The rendered
retained receipt now passes actual Tab/PageDown and automated checks; two
additional expiry/revalidation states have zero automated findings. Cutover is
opt-in only inside the disposable synthetic fixture; the native host gate,
installed services and database remain unchanged. Richer authoring, full
accessibility, approved deployment and production/live/lab gates remain open.
No integrated demo ran; full-product readiness remains false.

At the preceding r43 boundary, the
boundary record (private development evidence; not distributed) and
source-governance evidence (private development evidence; not distributed)
verify GUI source qualification and equivalent-generation mapping proposals,
author self-review denial, scoped-peer review and reasoned revocation. Quiet
proof becomes unavailable for revoked acceptance; sealed measurements and
review history remain. Controlled-fixture attestations are not independent
physical validation, production qualification, Situation coverage or incident
closure authority. Permanent cutover stays disabled. Three populated evidence
panels have named visible keyboard focus, real Tab/PageDown and zero automated
violations/incomplete findings; the historical retirement panel has only a
source regression, not rendered acceptance. Twenty UI regressions, twelve
fixture guards, native build/typing/lint, seven bundle/host cases and private
staging pass. Conditional cutover/retained receipt/recovery, richer authoring
and full accessibility remain open. No native cutover or integrated demo ran.

The inherited
Wi-Fi data-path evidence (private development evidence; not distributed)
adds normal GUI enrollment, sandbox authoring/publication, separately published
activation policy, explicit device approval and reasoned withdrawal. A bounded
synthetic HTTPS controller supplies one snapshot to actual packaged one-shot
Collector/Projection workers. PostgreSQL SQL, API and the dedicated Endpoints
page agree on IP/MAC/controller/AP/SSID/RSSI. Collection success and projection
success are checked separately; withdrawal blocks new dispatch after the next
run is due. These logical observations remain independently unverified and do
not authorize incident closure. R42 fixes success/RSSI contrast and gives
verification evidence named keyboard focus and PageDown scrolling. Nineteen UI
regressions, three HTTPS-fixture cases, native build/typing/lint, seven bundle/
host cases and private staging pass. Preceding
basic authoring (private development evidence; not distributed) and
populated GUI checks (private development evidence; not distributed) remain
inherited. MCP publication still does not register a tool, Skill publication
does not execute its loop, and zero-sample service views remain UNKNOWN.
Synthetic source collection is not live model/vendor/physical-device proof,
production TLS/mTLS, native component or full accessibility acceptance.
Conditional cutover/recovery, richer authoring, SVG/typography/transient and broader
assistive-technology/mobile checks remain open. Private fixtures are cleaned
up; no native cutover or integrated demo ran.

The r35 backend lineage coordinates the current backend, regenerated 73-pin offline
runtime, h5 migration, gateway, controllers and new production frontend.
All 460 packaged backend/resource files match source bytes; all 49 operator
files match the current deployment source. A private installed-wheel PostgreSQL
migration/RLS/backup-restore check passes. The packaged frontend serves 54
routes and 77 byte-equal referenced assets. Focused real required-auth browser
checks also verify GUI enrollment into private PostgreSQL, missing-IP inventory
rendering, CSRF, cross-tab namespace privacy and logout. Those checks do not install
the candidate or accept live-device data flow. See the
candidate record (private development evidence; not distributed).
The full ordinary collection now has 2,109 distinct terminal passes across
corrected segments, including 26 dedicated PostgreSQL opt-ins: 25 historical
schema checks and one current-schema catalog check. No missing, skipped or
unresolved nodes remain in that collection. R34 fixes certificate promotion discarded by fresh registry
admission and checks current identity after a row-lock wait. R35 fixes the legal
missing-IP inventory state found through an actual required-auth browser/API
check: list/page/detail reads allow null, the GUI labels the missing address,
and new monitoring enrollment still requires a valid IP. It is not a single
green full-suite run or complete installed/live-platform acceptance. The current
native collection now has 1,974 distinct terminal passes across corrected
segments and final r35 affected/selected-wheel checks, with no missing,
skipped or unresolved nodes. All generated databases/roles are gone and the
private test server is stopped; retained PostgreSQL/monitoring are unchanged.

GUI-approved continuous SNMP/Windows monitoring provides
explicit revisioned approval, renewal, withdrawal and finite expiry, with
identity/configuration/credential pins and retained public approval audit. A
separate database-free gateway maps intent to protected exporter custody,
checks current authority before and after every scrape and discards results
after withdrawal, rotation or expiry. Discovery errors clear target lists; a
cached list cannot authorize a scrape. API custody never owns exporter secrets
or monitoring configuration. Already dispatched reads can finish; SQL/file/
remote I/O are not atomic and no exactly-once or physical-truth claim is made.
See the [contract](docs/continuous-monitoring.md) and
record (private development evidence; not distributed).

The subsequent [metric query boundary](docs/metric-query-authorization.md)
constrains every parsed series selector before upstream aggregation/joins,
including raw scoped AI tools, and uses stable namespace/device-ID selectors
for device tools. Fresh current device membership/backend checks discard stale
output. It passes 60 focused source, ten disposable PostgreSQL and ten real
Prometheus evaluator checks. Parser string escaping is handled explicitly;
implicit `info()` reads and authorization-label rewrites are refused. Trusted
ingestion/evaluation remain requirements, not physical-device proof. Source
adds `promql-parser==0.10.0`, now included in r34; installed acceptance remains.
See the source checkpoint record (private development evidence; not distributed).

Current source migration head is `j7m9p1r3t5v8`; frozen r48 is
`h5k7m9p1r3t6`; installed r30 remains
at `g4j6l8n0p2r5`. The monitoring source checkpoint accounts for 59 distinct ordinary, 27
disposable PostgreSQL and 36 static identity cases, frontend typing/lint and a
synthetic real-browser journey. Gateway/native job installation, required-auth
live browser/ingestion and installed metric-series authorization remain open.
Source Agent/device query-label integration is complete at the checkpoint above.
There are now ten unaccepted required
native Python units and six reviewed controller roles awaiting provisioning.
No privileged deployment retry or integrated demo has run.

Ecosystem Transport completes source review of all nine internal controller SQL
profiles; six await native provisioning. Its fourteen relations/twenty-one
UPDATE columns manage delivery leases and append verified public evidence/audit,
not trust/credential configuration, private signing or capability publication.
Six genuine timestamp grants support shared locks; trust-key `created_at` is
explicitly writable, not pure SELECT authority. Fresh lease and current
endpoint/credential/witness/policy/key/domain fences surround bounded I/O;
witness evidence, both audits and terminal success commit atomically. Jobs are
claimed just before delivery rather than pre-leased as a waiting batch.
Targeted runs pass 86 ordinary and 43 exact-role native cases, including real
row contention, 21 SQL denials and four actual source-process crash boundaries
with natural expiry. Remote peers are fixtures; delivery remains at least once,
not exactly-once effects. The automatic newest-200 offer window is a disclosed
backlog/load limit. This source is now packaged in r34, not installed; r30 remains installed,
and production/live acceptance still precedes the demo. See the
Transport record (private development evidence; not distributed).

The preceding Capacity checkpoint has source acceptance: 12 explicit relations/five UPDATE columns,
fresh policy/mapping/deadline fences and a dedicated leader transaction across
business commits. Coordinated API registry locks serialize drain with claims,
renewal, heartbeat and re-registration. Four source-process crash boundaries
recover absolute simulated unit state without replaying completed start/stop;
receipts are not atomic external I/O. Corrected focused segments pass 95 distinct
ordinary and 35 native cases (32 exact Capacity role, three non-owner API
admission). This is not installed capacity convergence or live-fleet acceptance.
At that checkpoint, Ecosystem Transport was the only unreviewed profile and five
controllers awaited native provisioning. R34 batches these source changes with
the API admission fences; they are not enabled against installed r30. See the
Capacity record (private development evidence; not distributed).

Rollout and Scaling now have reviewed restricted internal SQL profiles and
source acceptance beyond the r31 freeze. Rollout advances approved automatic
rings using admitted candidate-only health plus current deployment/device/
credential/publication fences. Scaling appends recommendations under fresh
policy locks, never changes policy or applies capacity. Both bind a fixed
namespace and require transactional READ COMMITTED. Atomic publication and
real source-process loss/recovery pass focused checks: 62 distinct ordinary and
49 native cases across corrected segments. This is not installed/native fleet
or vendor acceptance. This earlier checkpoint is followed by Quality below;
at that earlier checkpoint, two controller profiles remained unreviewed and four
reviewed controllers awaited host provisioning. R34 now batches this source;
the historical r31 artifact does not represent current checkout bytes. See the
source evidence (private development evidence; not distributed).

Quality now also has source acceptance: a 35-relation profile, fresh policy and
publication identity fences, independent retained revocation checks and atomic
assessment/Alert/Situation publication. It cannot configure policy or change
runtime status/results/phase/targets/approval. Two explicit timestamp-only
evidence UPDATE grants support shared receipt locks; they are genuine authority,
not pure SELECT. Source/controlled-governance checks pass 126 distinct ordinary
and 44 native cases across corrected segments, including real process loss and
policy/publication waits. No model/vendor action, installed service, sustained
load or physical truth is claimed. See the Quality record (private development evidence; not distributed).

The Workflow Dispatch component now queues schedules, Alert triggers and
Situation integrations atomically with their initial checkpoint, execution
event, audit and terminal outbox state. Scheduled saved reports, retained proof
admissions/references, attachment bytes and namespace quota usage share that
transaction. Attempt/state/expiry fences reject stale completion and failure;
legacy committed results remain recoverable within the three-attempt boundary.
Current investigation-create permission and source Alert read/object scope are
rechecked independently of approved workflow configuration. Dispatch itself
does not call models or remote Tools; the independently authorized Agent loop
does that later.

An explicit internal dispatcher SQL profile and PostgreSQL/source-process
acceptance pass; 107 distinct focused ordinary and 60 native cases are verified.
Central principal/role/binding read metadata is a disclosed profile-specific
namespace-RLS exception, with timestamp-only UPDATE for retained-proof locks.
It is a trusted fixed-namespace service, never a tenant login or generated
capability credential. Native deployment of the packaged r31 candidate needs
explicit approval for the backend switch, new SQL login/grants and systemd
installation/lifecycle checks; the permission review rejected execution.
The installed backend remains r30 and the integrated demo remains deferred.
See the r31 evidence (private development evidence; not distributed).

## 1. Project Name

**Recommended name: `iCheck`**

`iCheck` is preferable to `Icheck` because it is visually cleaner, easier to read, and naturally suggests:

- **i** = intelligent / infrastructure
- **Check** = observe, verify, diagnose, validate

Possible positioning:

> **iCheck — AI-Native Infrastructure Operations**

Alternative tagline:

> **Observe. Understand. Act.**

---

# 2. Vision

iCheck is an **AI-native IT infrastructure agent platform** for monitoring,
investigation, management, and change governance.

It is not intended to be a traditional NMS with an AI chatbot added on top.

It is also not merely a monitoring product whose capabilities are fixed by the
vendor's release cycle. The product itself is an agent runtime and an in-product
capability studio. A user should be able to describe a requirement in natural
language and have iCheck create, test, publish, operate, and later revise the
required capability without leaving iCheck for a separate IDE.

The core idea is:

> The AI acts as an infrastructure engineer, while the GUI provides visualization, evidence, operational awareness, governance, and human authorization.

The intended product experience is closer to a general AI agent than a
traditional monitoring console:

```text
User states an operational purpose
             ↓
AI investigates or designs the missing capability
             ↓
iCheck validates it in a governed runtime
             ↓
User reviews evidence or an artifact diff
             ↓
The capability is published and becomes reusable by other agents
             ↓
The user iterates it through further conversation
```

The platform should combine:

- Infrastructure discovery
- CMDB / infrastructure knowledge
- Metrics
- Events
- Logs
- Topology
- Alerts and incidents
- AI investigation
- Root-cause analysis
- Infrastructure management
- Change automation
- Peer review
- Human approval
- Audit
- External platform integration
- In-product creation of collectors, topology views, tools, skills, and workflows
- Versioned capability publishing, validation, rollback, and reuse

---

# 3. Design Principles

## 3.1 AI-First, Not GUI-First

Traditional monitoring systems force users to navigate:

```text
Dashboard
  → Device
    → Interface
      → Metric
        → Logs
          → CLI
```

iCheck should instead allow:

```text
User:
"Why is the payment service slow?"

AI:
- identifies affected services
- checks application telemetry
- checks Kubernetes
- checks VM/host status
- checks network path
- checks interface health
- checks recent configuration changes
- correlates events
- produces evidence
- proposes remediation
```

The GUI remains important for:

- Topology
- Incidents
- Evidence
- Time series
- Configuration diffs
- Change review
- Approval
- Audit
- Asset browsing

---

## 3.2 The Product Is Its Own Capability Development Environment

Users must be able to extend iCheck from inside the running product through a
conversation with the AI. Creating a capability must not require a separate AI
coding agent, local IDE, source-code merge, or vendor software release.

First-class user-created artifacts include:

```text
Collector
Parser / normalizer
Entity and relationship mapping
Topology view
Metric and alert definition
Diagnostic or change tool
Skill
Deterministic workflow
Agentic workflow
Visualization
Report
```

These artifacts are executable specifications, not arbitrary prompt fragments.
Every artifact must have a schema, owner, permissions, version, test fixtures,
compatibility metadata, audit history, and rollback target.

The common authoring lifecycle is:

```text
CONVERSE
   ↓
DESIGN — AI produces a typed artifact and explains its assumptions
   ↓
VALIDATE — schema, policy, secret, dependency, and security checks
   ↓
TEST — sandbox execution against fixtures, replay data, or approved targets
   ↓
PREVIEW — output sample, topology preview, workflow trace, or configuration diff
   ↓
APPROVE — policy-driven human approval where required
   ↓
PUBLISH — immutable version enters the registry
   ↓
DEPLOY / RUN — scoped rollout with telemetry and health checks
   ↓
OBSERVE / ITERATE / ROLLBACK — continue through conversation
```

"User extensible" does not mean that an LLM may silently modify production code.
The AI may propose and generate artifacts, but deterministic platform controls
own validation, credentials, publishing, rollout, and rollback.

## 3.3 Everything Is an Entity, Relationship, Observation, Event, Artifact, or Tool

The internal data model should normalize infrastructure around five fundamental concepts.

### Entity

Examples:

```text
Device
Interface
Server
VM
Kubernetes Cluster
Pod
Database
Application
Storage Array
Site
Rack
Service
```

### Relationship

Examples:

```text
Device A --connected_to--> Device B
VM --runs_on--> ESXi Host
Pod --runs_on--> Kubernetes Node
Server NIC --connected_to--> Switch Interface
Application --depends_on--> Database
Device --located_at--> Site
```

### Observation

A time-related measured state.

Examples:

```text
CPU = 43%
Interface utilization = 72%
Optical RX = -4.8 dBm
BGP state = Established
Disk latency = 7 ms
```

### Event

Something happened.

Examples:

```text
Interface changed to DOWN
BGP adjacency reset
Configuration modified
VM restarted
SNMP trap received
Windows event generated
```

### Tool

A capability that an AI agent can call.

Examples:

```text
get_interface_status()
get_bgp_neighbors()
get_windows_cpu()
query_wmi()
ping()
trace_path()
restart_service()
configure_vlan()
```

### Artifact

A versioned capability created by iCheck, a vendor, or a user.

Examples:

```text
REST API collector for an internal IPAM
Wireless-controller terminal normalizer
WAN topology view
Payment latency investigation workflow
Windows service recovery skill
```

---

# 4. High-Level Architecture

```text
┌────────────────────────────────────────────────────────────────────┐
│                    AI-NATIVE PRODUCT EXPERIENCE                    │
│                                                                    │
│ AI Operator │ Assets │ Dashboards in Grafana │ Alerts │ Settings     │
│ Capability Studio: conversation, preview, test, enable                │
└────────────────────────────────┬───────────────────────────────────┘
                                 │ intent, feedback, approval
                                 ▼
┌────────────────────────────────────────────────────────────────────┐
│                         AGENT RUNTIME                              │
│                                                                    │
│ Supervisor │ Specialist Agents │ Planner │ Tool Loop │ Checkpoints │
│ Evidence   │ Budget / Stop Rules │ Human Interrupts │ Escalation   │
└──────────────────┬──────────────────────────────┬──────────────────┘
                   │ use capability              │ create/revise artifact
                   ▼                             ▼
┌──────────────────────────────┐   ┌─────────────────────────────────┐
│ CAPABILITY RUNTIME           │   │ CAPABILITY CONTROL PLANE        │
│                              │   │                                 │
│ Tool / Collector Runtime     │   │ AI Designer + Artifact Registry │
│ Workflow Engine              │   │ Versioning / Tests / Replay     │
│ Execution Router             │   │ Validation / Approval / Rollout │
│ MCP Client / Gateways        │   │ Compatibility / Rollback        │
└───────────────┬──────────────┘   └───────────────┬─────────────────┘
                └──────────────────┬───────────────┘
                                   ▼
┌────────────────────────────────────────────────────────────────────┐
│                    TRUST AND GOVERNANCE PLANE                      │
│ Policy │ RBAC │ Credential Broker │ Sandbox │ Audit │ Change Mgmt │
└────────────────────────────────┬───────────────────────────────────┘
                                 ▼
┌────────────────────────────────────────────────────────────────────┐
│                  DISTRIBUTED DATA AND EXECUTION PLANE              │
│                                                                    │
│ Site Collectors: API / SNMP / WMI-CIM / gNMI / Logs / Custom     │
│ Action Workers: Ansible / Nornir / Netmiko / PSRP / Vendor APIs   │
│ Knowledge: PostgreSQL │ Metrics: Prometheus │ Display: Grafana       │
│ Events / Logs │ Object Artifacts │ Queue / Scheduler               │
└────────────────────────────────────────────────────────────────────┘
```

The agent runtime is the product kernel. Monitoring, topology, and automation
are capabilities consumed and extended by that kernel rather than separate
legacy modules with a chatbot placed above them.

---

# 5. Core Modules

## 5.1 Infrastructure Knowledge / CMDB

PostgreSQL is the preferred primary database.

The CMDB should store relatively stable infrastructure objects.

### Core hierarchy

```text
Organization
  → Region
    → Site
      → Building
        → Room
          → Rack
            → Device
              → Component
                → Interface
```

### Example device attributes

```text
device_id
hostname
vendor
model
serial_number
os
os_version
management_ip
site
rack
device_role
resource_type
monitoring_profile
credential_profile
lifecycle_state
```

---

## 5.2 Dynamic Infrastructure State

Dynamic operational information should not be treated as static CMDB fields.

Examples:

```text
ARP table
MAC table
LLDP neighbors
CDP neighbors
interface operational state
routing table
BGP state
OSPF state
wireless client associations
VM state
Kubernetes pod state
```

These should use:

```text
first_seen
last_seen
observed_at
source
confidence
```

This allows AI to reason about change over time.

---

# 6. Discovery Engine

Discovery is responsible for building and maintaining the infrastructure knowledge model.

Possible discovery methods:

```text
SNMP
ICMP
LLDP
CDP
ARP
MAC address tables
REST APIs
NETCONF
gNMI
SSH
WMI/CIM
VMware API
Kubernetes API
Cloud APIs
```

Example discovery flow:

```text
Seed IP
  ↓
SNMP sysObjectID
  ↓
Identify vendor/model
  ↓
Collect interfaces
  ↓
Collect LLDP/CDP
  ↓
Discover neighbors
  ↓
Collect ARP/MAC
  ↓
Update topology
  ↓
Repeat
```

## 6.1 Generalized Collector Runtime

SNMP is one collector implementation, not the definition of collection in
iCheck. Any source that can produce observations, events, entities, or
relationships through a stable contract can become a collector.

Supported collector transports may include:

```text
REST / GraphQL / SOAP
SNMP
gNMI / NETCONF
SSH / CLI
WMI / CIM / PSRP
SQL
Prometheus scrape
OpenTelemetry
Syslog / traps / event streams
Cloud and SaaS SDKs
Files and object storage
User-defined APIs
```

A collector artifact must define:

```yaml
metadata:
  name: internal-ipam
  version: 1.0.0
  owner: network-platform

connection:
  protocol: http
  credential_profile: ipam-readonly

schedule:
  mode: poll
  interval: 300s

input_schema: {}
output_contract:
  - Entity
  - Relationship
  - Observation

normalization: {}
health_checks: {}
rate_limits: {}
test_fixtures: {}
permissions: {}
```

The in-product AI Collector Designer should accept an API description, sample
payload, MIB, command output, or plain-language requirement and generate the
collector definition, parser, mappings, tests, and preview.

Any Collector that targets a registered Device must declare that Device ID and
bind its deployment to the Device's reviewed identity revision. The approved
target, site, and binding belong in the immutable plan evidence. A name,
address, site, or credential-binding correction invalidates the old deployment;
the Agent cannot silently retarget it. Worker assignment and on-demand execution
must reject a stale binding. Non-device sources may remain unscoped, but a
generated Collector that could point to a registered Device must not evade
review by hiding its target in an arbitrary URL or hostname.

Implementation boundary: API/vendor descriptions may be attached to REST,
OpenAPI, or fixed-command sessions only as bounded, sanitized, untrusted
semantic context. They never replace the representative sample or schema as
the deterministic field authority, and cannot directly produce executable
code or bypass validation and publication gates.

Collectors must run in a distributed collector plane:

- Assign targets by site, tenant, protocol, or consistent shard.
- Use leases and heartbeats so failed work can be reassigned.
- Apply per-target concurrency, timeout, retry, jitter, and backpressure.
- Buffer transient failures without writing directly to core database tables.
- Report collector version, health, lag, and coverage to the control plane.
- Support systemd/VM deployment as the production baseline; containers remain
  an optional packaging choice.
- Authenticate distributed HTTP Workers with both a rotating bearer token and
  a unique client certificate verified by a private trusted proxy. Bind only a
  SHA-256 identity and validity metadata; serialize cross-pool claims, stage
  cutovers, support cancellation, and invalidate the token during emergency
  revocation. A previously bound Worker must fail closed if mTLS is disabled.

---

# 7. Monitoring Categories

Initial resource categories:

```text
Network
  - Wired
  - Wireless
  - Firewall
  - Load balancer
  - OOBM

Compute
  - Linux
  - Windows

Virtualization
  - VMware
  - Hyper-V

Storage
  - SAN
  - NAS
  - Storage arrays

Application
  - Services
  - APIs
  - Middleware

Database
  - MySQL
  - PostgreSQL
  - SQL Server
  - Oracle

Container
  - Kubernetes
  - Docker

Cloud
  - AWS
  - Azure
  - GCP
```

Internally these should not be rigid categories.

Use:

```text
resource_type
+
capabilities
```

Example:

```yaml
resource_type: network.switch

capabilities:
  - snmp
  - ssh
  - lldp
  - interfaces
  - bgp
  - ospf
  - configuration
```

---

# 8. SNMP Collection Platform

SNMP support is an initial built-in collector pack implemented on the generalized
collector runtime. It must not introduce SNMP-specific assumptions into the
entity, observation, scheduling, or artifact models.

Recommended design:

```text
Device
  ↓
SNMP
  ↓
SNMP Exporter / custom collector
  ↓
Prometheus-compatible ingestion
  ↓
Time-Series Database
```

Recommended components:

```text
Prometheus SNMP Exporter
Prometheus
VictoriaMetrics / Mimir / Thanos for larger deployments
```

---

# 9. AI-Generated SNMP Templates

Users should not need to manually write SNMP monitoring profiles.

Target workflow:

```text
User uploads MIB
        ↓
Trusted bounded parser minimizes MIB and resolves numeric OIDs
        ↓
AI selects only useful known symbols
        ↓
AI classifies:
- counter
- gauge
- status
- table
        ↓
AI generates SNMP profile
        ↓
Platform compiles numeric-OID generator proposal
        ↓
External SNMP Exporter generator attestation
        ↓
Test walk against device
        ↓
Cardinality validation
        ↓
Preview
        ↓
Deploy
```

"No human interference" should mean:

> No manual template authoring is necessary.

However automated validation must always be retained.

---

# 10. Time-Series Metrics

The engineering preview uses the existing Prometheus instance. Exporters and
adapters translate SNMP, HTTP APIs, host, container and VMware measurements into
scrapable metrics. Grafana is the only monitoring metric presentation layer:

```text
Device or API → exporter/adapter → Prometheus → Grafana dashboard
                                      ↑               ↑
                            scoped AI queries   approved AI dashboard edits
```

Keep PromQL as a bounded AI-callable tool. Remote-write storage and fleet scale
are later extensions, not preview prerequisites. PostgreSQL retains inventory,
IP/MAC/Wi-Fi history and operational evidence, not a duplicate time-series store.

For “Show interfaces over 80% utilization during the last 30 minutes,” the AI:

1. discovers actual counters, labels and interface speed;
2. validates and executes a bounded PromQL query;
3. explains results and missing evidence;
4. finds or proposes a Grafana dashboard and returns a contextual link;
5. saves a new or revised dashboard only after confirmation.

No iCheck React chart is generated. See the
[Grafana integration design](docs/grafana-monitoring-design.md).

---

# 11. Event and Log Platform

Metrics are insufficient for root-cause analysis.

The platform should collect:

```text
SNMP traps
Syslog
Windows Event Logs
Kubernetes Events
VMware events
Application logs
Cloud events
Configuration-change events
Security events
```

Potential components:

```text
OpenTelemetry Collector
Loki
OpenSearch
ClickHouse
Kafka / Redpanda if event volume requires it
```

---

# 12. Tool / Capability Platform

This is a core differentiator of iCheck.

The AI should not directly control infrastructure.

It should call structured tools.

Example:

```python
get_bgp_neighbors(device_id)

get_interface_status(
    device_id,
    interface
)

query_windows_cim(
    server,
    namespace,
    class_name
)

ping(
    source,
    destination
)

configure_vlan(
    device,
    vlan_id,
    name
)
```

---

# 13. Tool Definition

Every tool should include metadata.

Example:

```yaml
name: get_bgp_neighbors

category: diagnose

risk: low

permission: read_only

input_schema:
  device_id: string

output_schema:
  neighbors: array

timeout: 10

credential_profile:
  network_readonly

audit: true
```

Write tool:

```yaml
name: configure_vlan

category: change

risk: medium

permission: write

peer_review_required: true

rollback_supported: true

audit: true
```

---

# 14. User-Customizable AI Tools

The system should allow users to create new tools using AI.

Supported tool types:

```text
HTTP / REST
Python
SQL
Shell
SNMP
SSH
WMI / CIM
PowerShell
NETCONF
gNMI
Kubernetes API
MCP
```

Example request:

```text
"Create a tool that queries our IPAM API
and returns the owner, VLAN and site for an IP."
```

AI generates:

```text
lookup_ip_owner(ip)
```

The generated tool must pass:

```text
schema validation
security validation
permission validation
sandbox testing
test execution
approval before publishing
```

---

# 15. Execution Framework Strategy

iCheck should support several execution engines.

They serve different purposes.

## 15.1 Ansible

**Primary management and change automation framework.**

Best use cases:

```text
Multi-vendor configuration
Server management
Windows management
Linux management
VMware
Kubernetes
Cloud
Storage
Deployment workflows
Idempotent configuration
Rollback workflows
```

Ansible should be the default engine for controlled infrastructure changes.

---

## 15.2 Nornir

Nornir should remain available for Python-native network workflows.

Good use cases:

```text
Fast ad-hoc diagnostics
Parallel network queries
Custom Python workflows
Agent-created diagnostic tools
Complex result processing
```

Nornir is not required for every operation but should be supported as a first-class execution backend.

---

## 15.3 Netmiko

Netmiko should provide direct CLI access where structured APIs are unavailable.

Examples:

```text
show ip bgp summary
show interface counters
show mac address-table
show ip route
show environment
```

Use Netmiko primarily as a driver behind tools.

The AI should normally not directly construct arbitrary CLI commands.

---

## 15.4 Paramiko

Paramiko should normally remain below the platform abstraction.

Direct Paramiko use should be minimized.

Preferred hierarchy:

```text
Structured API
   ↓
gNMI / REST / NETCONF
   ↓
Ansible / Nornir
   ↓
Netmiko
   ↓
SSH
```

---

# 16. Execution Router

A central capability engine should decide how to execute a tool.

Example:

```text
get_bgp_neighbors(LEAF01)
        ↓
Capability Engine
        ↓
Device supports eAPI?
   YES → eAPI
   NO
        ↓
NETCONF?
   YES → NETCONF
   NO
        ↓
Nornir + Netmiko
```

For a configuration change:

```text
configure_vlan()
        ↓
Capability Engine
        ↓
Ansible resource module
        ↓
vendor collection
```

---

# 17. Windows / WMI / CIM Support

Windows is a first-class platform.

Preferred mechanisms:

```text
PSRP
WinRM
PowerShell
CIM
WMI
Windows Event Log
windows_exporter
```

Modern queries should prefer CIM.

Examples:

```powershell
Get-CimInstance Win32_Processor

Get-CimInstance Win32_LogicalDisk

Get-CimInstance Win32_OperatingSystem
```

Hyper-V example:

```powershell
Get-CimInstance `
  -Namespace root\virtualization\v2 `
  -ClassName Msvm_ComputerSystem
```

AI tool:

```text
get_hyperv_vm_cpu(vm_name)
```

Possible implementation:

```text
AI
 ↓
Tool Registry
 ↓
Ansible
 ↓
win_powershell
 ↓
PowerShell
 ↓
CIM
 ↓
Hyper-V
```

---

# 18. Capability Model

Every resource should expose four groups of capabilities.

```text
RESOURCE
  │
  ├─ Observe
  ├─ Diagnose
  ├─ Manage
  └─ Change
```

Example: Network Switch

```text
Observe
- CPU
- memory
- interfaces
- environmental state
- BGP

Diagnose
- ping
- traceroute
- route lookup
- BGP lookup
- MAC lookup
- ARP lookup

Manage
- backup config
- save config
- reboot
- software upgrade

Change
- VLAN
- interface
- ACL
- BGP
- routing policy
```

Example: Windows Server

```text
Observe
- CPU
- memory
- disk
- services

Diagnose
- CIM/WMI query
- Event Log
- process inspection
- connectivity test

Manage
- start service
- stop service
- restart service
- reboot
- Windows Update

Change
- registry
- firewall
- software installation
- system configuration
```

---

# 19. Tool Risk Classification

Tools must be classified according to operational risk.

## Level 0 — Observe

Examples:

```text
get_cpu()
get_interface()
get_route()
get_metric()
```

Approval:

```text
No peer review required
```

---

## Level 1 — Diagnose

Examples:

```text
ping()
traceroute()
WMI query
show commands
log query
```

Approval:

```text
No peer review required
```

---

## Level 2 — Operational Management

Examples:

```text
restart_service()
clear_bgp_session()
reboot_server()
```

Approval:

```text
Change Request
Peer Review
```

---

## Level 3 — Configuration Change

Examples:

```text
configure_vlan()
modify_acl()
change_bgp_policy()
modify_firewall_policy()
```

Approval:

```text
Change Request
Peer Review
```

---

## Level 4 — High-Risk Change

Examples:

```text
upgrade_core_switch()
delete_vm()
change_core_firewall_policy()
database schema modification
```

Approval:

```text
Change Request
Peer Review
Privileged Reviewer
Maintenance Window
Additional policy checks
```

---

# 20. Change Governance

Any state-changing action must create a Change Request.

The AI must never directly perform a production state change.

Workflow:

```text
AI Recommendation
      ↓
Proposed Change
      ↓
Pre-check
      ↓
Impact Analysis
      ↓
Risk Analysis
      ↓
Generate Diff
      ↓
Rollback Plan
      ↓
Peer Review
      ↓
Approval
      ↓
Maintenance Window
      ↓
Execution
      ↓
Post-check
      ↓
Success?
   /       \
 Yes       No
  │         │
Close     Rollback
```

---

# 21. Peer Review / Four-Eyes Principle

The system must enforce:

```text
Requester != Reviewer
```

Example:

```text
Alice creates change
Bob reviews change
Bob approves
```

Alice cannot approve her own change.

The rule must be backend enforced.

---

# 22. Change Object

Example:

```json
{
  "change_id": "CHG-20260914-001",
  "requested_by": "AI-Agent",
  "requested_for": "Incident-4832",

  "targets": [
    "CORE-HK-01",
    "CORE-HK-02"
  ],

  "change_type": "network.bgp.policy",

  "reason": "Move traffic away from degraded ISP-A",

  "risk": "medium",

  "current_state": {
    "local_preference": 100
  },

  "desired_state": {
    "local_preference": 200
  },

  "affected_services": [
    "internet",
    "payment-service"
  ],

  "peer_review_required": true,

  "rollback_supported": true
}
```

---

# 23. Change Review GUI

The reviewer should see business and operational meaning, not only YAML.

Example:

```text
CHANGE CHG-20260914-001

AI Proposed

Increase BGP Local Preference
ISP-B: 100 → 200

Targets
CORE-HK-01
CORE-HK-02

Reason
ISP-A packet loss = 14.7%

Expected Result
Approx. 65% outbound traffic moves to ISP-B

Risk
MEDIUM

CONFIG DIFF
- local-preference 100
+ local-preference 200

PRE-CHECK
✓ ISP-B healthy
✓ capacity sufficient
✓ BGP established
✓ rollback available

[Reject] [Request Modification] [Approve]
```

---

# 24. Incident Model

iCheck should separate:

```text
Event
Alert
Incident
```

## Event

Something happened.

```text
Ethernet1 changed state to DOWN
```

## Alert

A monitoring condition was violated.

```text
BGP neighbor unavailable
```

## Incident

Multiple events and alerts describe one operational failure.

Example:

```text
Ethernet1 down
BGP down
packet loss high
application unreachable

        ↓

AI Correlation

        ↓

Incident:
HK WAN connectivity degradation caused by
PE01 Ethernet1 physical failure
```

---

# 25. Alert / Incident Center

The primary operational screen should show incidents instead of thousands of individual alerts.

Example:

```text
CRITICAL INCIDENT #4832

HK Edge Connectivity Degradation

Started:
14:31:06

Affected services:
23

Likely root cause:
PE01 Ethernet1 physical-layer failure

Confidence:
96%

Correlated:
1 physical alarm
1 BGP alarm
3 route changes
11 service alarms
17 application symptoms
```

---

# 26. External Integration

The platform should expose APIs and webhooks for:

```text
ServiceNow
Jira
PagerDuty
Teams
Slack
Email
OA platforms
ITSM systems
CMDB systems
IPAM systems
custom ticket systems
```

Integration should be bidirectional.

Example:

```text
iCheck detects incident
      ↓
creates ServiceNow ticket
      ↓
adds AI RCA
      ↓
updates investigation progress
      ↓
records remediation
      ↓
verifies recovery
      ↓
closes ticket
```

---

# 27. Topology

Topology is one of the GUIs that should definitely remain.

However, it should represent infrastructure relationships rather than only physical links.

Example:

```text
Application
     ↓
Kubernetes Service
     ↓
Pod
     ↓
Node
     ↓
VM
     ↓
Hypervisor
     ↓
NIC
     ↓
Switch Interface
     ↓
Leaf
     ↓
Firewall
     ↓
WAN
```

The AI should dynamically filter topology according to the investigation.

Example question:

```text
"Why can't 10.20.17.21 reach 10.50.8.33?"
```

UI:

```text
10.20.17.21
     ↓
Leaf12
     ↓
Spine02
     ↓
FW03  ← DENY
     ↓
Leaf21
     ↓
10.50.8.33
```

---

# 28. AI Investigation Workspace

This should be the primary UI.

Example:

```text
Investigating:
HK office packet loss

✓ Checked WAN health
✓ Checked firewall status
✓ Checked router interfaces
✓ Checked historical baseline
● Checking BGP changes
○ Checking recent configuration changes
○ Testing hypothesis
```

The system should expose what the AI is doing instead of displaying a generic "Thinking..." indicator.

---

# 29. Evidence Model

Every AI conclusion must expose supporting evidence.

Example:

```text
Conclusion:

BGP instability caused by physical interface degradation.

Confidence:
93%

Evidence:

Ethernet4 CRC:
14:00      3
14:20      3
14:31  14839

Optical RX:
-18.2 dBm

Normal range:
-4.3 to -5.1 dBm

BGP:
Established → Idle at 14:31:05
```

The AI provides abstraction.

The GUI provides proof.

---

# 30. Configuration & Change Intelligence

The platform should collect and correlate:

```text
running configuration
configuration versions
configuration diffs
who changed it
when it changed
source of change
Git history
automation deployment
firmware upgrade
policy change
```

AI should be able to answer:

```text
"Did anything change before the outage?"
```

Example:

```text
14:59:47 ACL WAN_OUT modified
15:00:12 BGP began resetting
15:01:04 Application latency alarm

Correlation confidence: 97%
```

---

# 31. Dynamic UI Philosophy

Grafana owns metric visualization. iCheck owns the engineer's operational task.

The default home screen is the AI L1 operator workspace, not an inventory or
metric dashboard. It should show only information that requires attention:

```text
AI shift summary
Prioritized alerts and evidence gaps
Investigations currently being performed by AI
Pending human approvals
Collection gaps and uncertainty that block reasoning
```

Raw endpoint tables, device inventories, full alert lists, and protocol-specific
details belong in contextual drill-down pages. The AI may bring them into an
investigation when they are evidence, but they should not dominate the home
screen.

Users should be able to request:

```text
"Show WAN utilization for all Hong Kong sites
during the last seven days."
```

AI finds or generates the Grafana dashboard definition, using observed metrics,
and opens Grafana with the relevant target and time range. It does not generate
custom iCheck chart components.

Users can then say:

```text
"Split by ISP."

"Compare with last week."

"Highlight anomalies."

"Save this view."
```

Confirmed dashboard revisions are persisted in Grafana. iCheck retains their
capability version, remote UID, change receipt and restoration data.

---

# 32. Main Navigation

Target preview navigation:

```text
iCheck

AI Operator
Assets
  - Devices and enrollment
  - Interfaces and IP/MAC/Wi-Fi history
Dashboards (Grafana)
Alerts
Capability Studio
  - Conversation-first builder
  - Installed templates and extensions
Activity (investigations, runs and approvals)
Settings
  - AI Providers and Models
  - Prometheus and Grafana
  - Plugins and optional MCP
  - Credentials
  - Access and Audit
```

Services and Service Intelligence are removed from the supported product journey.
Legacy custom metric views move to Grafana. Existing backend records remain
until dependent workflows are migrated; removal of a menu is not permission to
delete inventory or investigation history. Engineers can still open supporting
pages directly; conversation is the primary path, not a barrier to manual use.

The dated entries below describe previous implementation, not this target UI.

Implementation status on 2026-09-18: `Assets → Devices` is implemented as a
dedicated drill-down and onboarding route at `/assets/devices`. It supports
device identity, site and labels, protocol-neutral connection intents, and
scoped external credential references. It is intentionally separate from the
AI Operations home. New-device credential choices are constrained by adapter
and site Worker scope; changing site after a selection exposes an ineligible
reference and blocks submission until the operator corrects or clears it.
Server validation remains authoritative. Connection creation produces `pending` verification state.
Authenticated site workers now claim leased preflight jobs and return bounded
evidence for ICMP, TCP transport, or SNMP Exporter protocol queries; the Assets
page exposes the latest result and audited retry. Verified connections can now
be rendered through versioned, published activation policies into deterministic
collector-deployment plans. The Assets page exposes the plan and warnings; an
operator must approve its hash and reason before atomic activation, and can
later deactivate it without deleting history. A connection now owns multiple
stable capability slots: SNMP metrics and governed LLDP/CDP topology can run
together, each with independent health and exact deactivation. A new published
version of the same capability atomically disables its prior deployment. This state is
`monitoring_configured`, not `active`. Runtime reconciliation now promotes only
fresh successful scheduled collection to `active`, degrades failed or stale
collection, fingerprints approved deployment content, detects drift, and
requires a new exact-plan approval to repair it. Live lab and scale acceptance
remain open, so neither transport verification nor saved configuration alone is
presented as proof of continuous monitoring.

Implementation status on 2026-10-04: device metadata and reviewed target
identity now have separate revision counters. Activation plans, direct
deployments, and device-scoped canaries bind the latter; scheduled claims and
on-demand triggers fail closed after identity change. A migration disables
unreviewed legacy scoped deployments for reapproval. Functional API, populated
SQLite migration, and disposable non-owner PostgreSQL RLS/lock-wait tests pass.
Studio still needs to require an explicit binding for every generated
device-targeting Collector; unscoped arbitrary URLs cannot yet be attributed
to an inventory Device automatically.

Implementation status on 2026-09-29: terminal identity now has its own
`/assets/endpoints` evidence workspace instead of appearing on the AI L1 home
or being mixed into Device onboarding. It provides searchable MAC/hostname/IP
identity, current IP sources, wired collector/interface/VLAN attachment, and
Wi-Fi controller/AP/SSID/band/channel/RSSI/SNR state. Controller and collector
references resolve to scoped Device names. The Agent continues to receive a
separate bounded history projection that omits usernames and raw vendor
payloads.

Implementation status on 2026-09-30: the M2 Agent now also has a
controller-centric `wireless.list_controller_clients` Tool over that normalized
session store. It requires an exact authorized wireless-controller Device,
bounds freshness and rows, supports exact AP/SSID plus weak RSSI/SNR filters,
and returns MAC/IP/radio evidence without endpoint usernames or raw controller
payloads. This complements, rather than duplicates, endpoint-centric history.

Implementation status on 2026-09-21: credentialed collector runs now use a
lease-bound resolution grant. The control plane revalidates Worker ownership,
lease, adapter, and label scope but returns only provider metadata and an
external reference. Site Workers resolve HashiCorp Vault KV v2 references with
a local token file, hold values only for the assignment, redact raw and derived
secret echoes from envelopes/errors/logs, and clear the runtime mapping after
execution. Environment resolution is explicit development-only behavior, and
non-loopback control-plane connections require HTTPS unless an isolated-lab
override is deliberately enabled. The production PSRP transport is implemented;
production Vault rotation/renewal and representative Windows/JEA execution
remain acceptance gates.

Implementation status on 2026-09-21: the first generated implementation
runtime is also complete. `python_sandbox_v1` is limited to pure transforms
after a trusted, allowlisted HTTP fetch, so generated code never receives a
socket or credential. Each fixture and runtime transform runs in a separate
process under AST policy, Landlock filesystem denial, seccomp network/process/
privilege denial, no-new-privileges, rlimits, empty environment, bounded I/O,
and timeout. Exact-output fixtures gate publication and their hashes/results are
stored on the immutable Artifact version.

Implementation status on 2026-09-25: normalized Collector envelopes now close
the first durable collection-to-knowledge loop instead of stopping at a staging
table. Every accepted non-canary envelope atomically creates one
`KnowledgeProjection`; source plus idempotency key prevents duplicate staging
and the one-to-one queue prevents duplicate projection. Independent
`icheck-projection-worker` processes require PostgreSQL and claim with
`SKIP LOCKED`, hash-only lease tokens, deadlines, bounded retry/dead letter,
and crash reassignment. Completion conditionally rechecks status, Worker,
token, and deadline in the same transaction as domain writes, so an expired
Worker cannot overwrite a replacement or leave partial knowledge.

The initial explicit contracts project network observations into endpoint,
IP, and wired-attachment history; complete controller snapshots into endpoint,
IP, and Wi-Fi terminal state plus RSSI rules; and events into stateful Alerts
and any activated Alert Workflow. Strict versioned payloads, declared
CollectorDefinition output kinds, inline-secret policy, and the originating
deployment's device/site scope are rechecked. Unknown types are retained and
marked ignored rather than guessed. Scoped health/list/retry APIs and the AI L1
Collection Gaps rail expose Worker availability, queue age, retry, and
dead-letter evidence without raw payloads. Migration backfills existing
envelopes, and a hardened systemd unit supports bare-metal horizontal scale.
The first generic Entity/Relationship contracts and the PostgreSQL 1,000-target
failure/capacity gate were the next foundations.

Implementation status on 2026-09-25: strict
`icheck.knowledge.entity/v1` and `icheck.knowledge.relationship/v1` contracts
now let a published user Collector extend the operational graph without direct
database access or a core schema change. The platform derives a stable Artifact
namespace and exact device/site scope, bounds normalized attributes, preserves
first/last-seen while preventing older observations from regressing current
state, canonicalizes undirected edges, and commits graph provenance with the
same lease-owned projection transaction. Scoped read APIs expose the graph,
and Topology Studio can catalog, validate, and preview its types while omitting
arbitrary attributes. The M2 kernel now also exposes `knowledge.query_graph`, a
scope-checked, one-hop, 50-edge maximum read tool selected by durable ID or an
unambiguous type/external-key pair; its result and evidence omit arbitrary
attributes. Broader specialized projections and multi-hop situation reasoning
remain iterative capability work rather than prerequisites for adding a new
source type.

Implementation status on 2026-09-25: a dedicated `icheck-scale-test` acceptance
harness now exercises the real Collector claim/ingest/complete path and the
real Knowledge Projection claim/process path with two or more Workers in each
phase. It deterministically expires both lease types, proves reassignment and
stale-owner denial, refuses application or non-empty databases, and produces a
versioned JSON report covering latency percentiles, achieved cycle time,
throughput, CPU, resident memory, PostgreSQL growth, Worker balance, retries,
dead letters, timeouts, and simulated series cardinality. SQLite is allowed
only as explicitly non-representative smoke coverage. This server does not
currently have an active PostgreSQL service, so the representative 1,000-target
run and operating-system process-kill evidence remain open and are not claimed
as completed. The 2026-09-25 SQLite path check at schema head `1d5b9f7a4c82`
did process 1,000 complete target cycles with balanced Worker participation,
both forced reassignments, no errors/dead letters/timeouts, 11.34-second
projection p95, 21.46-second wall time, and 177.50 MiB process peak RSS; these
figures are diagnostic evidence, not production sizing.

Implementation status on 2026-09-21: the first conversational Capability
Studio slice is now implemented at `/studio`. An authorized user describes a
REST collector and supplies sanitized representative JSON; a governed
`capability.authoring` model route returns a strict mapping specification, not
executable code. The platform proves paths against the sample, compiles the
fixed transform template, runs an exact-output fixture through the real sandbox,
and creates an immutable draft. Human publication is explicit. A follow-up
conversation creates another version, while a sandbox-rejected draft remains
traceable and retryable. This was the first Studio slice; the later
implementation records below add semantic diff, replay, canary promotion,
portable and signed import, Tool/Skill activation, Workflow execution, and the
published live topology runtime. Broader generated adapters remain later M3
work.

Implementation status on 2026-09-27: a local Capability Catalog is now
available at `/studio/catalog` and `/api/v1/capability-catalog`. It is separate
from the Artifact Library: the Library describes lifecycle history, while the
Catalog recomputes whether each current published version is operator-ready.
Collector deployment state, MCP Tool activation and registry/server binding,
Skill/Workflow dependency snapshots, Workflow trigger activation, Topology
contract validity, required permissions, and signed-import provenance are
projected into bounded summaries and stable blocker codes. Arbitrary Artifact
definitions, schemas, labels, deployment inputs, credentials, and raw runtime
errors are not exposed. Published readiness now also identifies exact signed
organization-pack origin. Remote organization discovery, governed acquisition,
revocation/update feeds, purpose-scoped organization trust distribution,
dual-controlled trust-root rotation, and the external transparency
witness/gossip foundation plus durable automated witness/promotion transport
and quorum-backed regional gossip plus manual atomic promotion publication are
implemented. The private-key-free HSM/KMS recovery signing gateway, local
verification, quorum assembly, and immutable evidence lifecycle are also
implemented. Prebound enterprise OIDC Authorization Code/PKCE browser identity
and source/secret-bound trusted-proxy browser identity are also implemented.
CI workload OIDC/JWT exchange is implemented with exact service-Principal
prebinding, one-time jti consumption, bounded workload-linked tokens, and
immediate identity-disable enforcement. Governed group/role mapping, live
IdP/identity-gateway/CI-provider/vendor-gateway acceptance, and recovery drills
remain ecosystem work. Outbound exchange mTLS is implemented separately as
described below.

Implementation status on 2026-09-29: signed organization packs now provide the
first Phase 6 distribution boundary at `/studio/catalog/packs`. An external
signer creates `icheck.capability-pack.signed/v1`; iCheck verifies its trusted
Ed25519 key, canonical digest, exact `icheck/0.1` platform API, every embedded
portable Artifact, name conflicts, and exact in-pack or published-local
dependencies. Installation reruns target validators inside one transaction,
reuses exact installed versions, rolls everything back on any failure, and
records immutable pack/Artifact provenance. It does not publish, activate,
deploy, schedule, or execute a capability. Trust distribution/rotation and the
signed promotion layer described below preserve those same lifecycle gates.

Implementation status on 2026-09-29: signed pack revocation is now a separate
runtime security control. An organization authority signs a strictly
monotonic `icheck.capability-pack.revocations.signed/v1` digest feed with an
existing trusted Ed25519 identity. Admin-only ingestion validates provenance,
time, sequence, and exact pack digests, then records the feed and atomically
quarantines content introduced by matching installed packs. Quarantine
deprecates published versions, disables and unleases Collector deployments,
aborts canaries, deactivates MCP Tools, disables Workflow triggers/schedules,
immediately cancels bound Skill/Workflow Agent executions, and turns off
Service Indicator and Situation integration bindings. Preview, install,
publish, and canary boundaries prevent ordinary reactivation. Reused versions
are not treated as introduced by the revoked pack. The dedicated pack page
shows the signed revocation ledger and bounded quarantine result. Trust
distribution/rotation, transparency, and signed target qualification are
implemented without weakening quarantine.

Implementation status on 2026-09-29: compatible signed pack upgrade is now
implemented without weakening lifecycle governance. The successor's signed
manifest names the exact current predecessor digest; iCheck also requires
strict semantic-version advancement, signer continuity, and proof that each
changed Artifact identity was introduced rather than merely reused by the
predecessor lineage. The predecessor is locked and rechecked, target validators
run against every new version, and the installation/version/provenance records
commit or roll back together. Successful upgrade creates only validated
candidates and leaves publication, deployment, activation, scheduling, and
execution unchanged. Explicit signer rotation is now handled by the dual-signed
trust transition described below.

Implementation status on 2026-09-29: compatible pack uninstall now uses a
preview-first, digest-bound transaction rather than deleting provenance. Only
the current lineage head is eligible; active signed successors and exact
downstream pack dependencies fail closed. Execution deprecates only Artifact
versions introduced by that installation, reuses the revocation quarantine
primitive to stop bound Collector, MCP, Workflow, Skill, indicator, and
integration paths, and records the human reason plus bounded impact summary.
Retained/reused versions and the signed installation ledger remain intact.
Removing an upgrade restores its installed predecessor as lineage head. Exact
removed digests cannot be replayed, while a higher same-signer successor may
recover a fully removed lineage from its latest tombstone.

Implementation status on 2026-09-29: signed remote organization catalog
discovery is available at `/studio/catalog/remote`. Each source pins an exact
catalog identity, HTTPS URL/host allowlist, and enabled Ed25519 trust key.
Manual refresh uses bounded no-redirect transport and verifies canonical
digest, source identity, signer, issue/expiry window, monotonically increasing
sequence, unique pack identities/digests, and allowlisted HTTPS pack URLs.
Successful snapshots store only normalized metadata. Current discovery excludes
disabled or expired sources and joins local installation/tombstone, revocation,
pack-signer trust, and platform compatibility.

The same Studio page now provides explicit governed acquisition. Preview and
install independently refetch through bounded no-redirect HTTPS, first require
the entry to remain current, enabled, unexpired, non-revoked, and allowlisted,
then match the downloaded signed pack to every pinned identity/count field.
Both paths rerun full pack signature, embedded Artifact, dependency, target,
revocation, and lineage validation. Install stores the catalog/source/snapshot/
entry/sequence/index-digest provenance and stops at validated; it does not
publish, activate, deploy, schedule, or execute. Trust distribution, external
transparency witnesses, and cross-environment promotion are separate,
implemented governed controls.

Implementation status on 2026-09-29: cross-environment qualification is
implemented at `/studio/catalog/promotions`. Local policy pins environment and
stage; each trusted source binds organization/environment/stage to an exact
purpose-isolated public key and contiguous sequence. The source exports a
canonical statement binding the installed pack, Artifact-set digest, validation
evidence, exact target/stage, and source transparency checkpoint for external
signing. Target preview and acceptance revalidate signature, sequence, pack
lineage, revocation, signer trust, Artifact state, and dependencies. Acceptance
persists an exportable receipt and transparency event atomically but never
publishes or activates automatically. Durable delivery to a pinned target and
an opt-in four-eyes atomic publication decision are implemented; CI/CD identity
federation acceptance, live emergency environment-key recovery, live witnessed
source heads and live handover acceptance remain production gates. Planned
dual-signed key handover and required target-local checkpoint witness policy
are implemented as described below.

Implementation status on 2026-09-30: the separate Ecosystem Exchange surface
pins allowlisted HTTPS endpoints to one independent witness identity or exact
promotion environment/stage. A standalone PostgreSQL-leased worker
automatically reconciles checkpoint offers, resolves optional server-side
credentials only at send time, uses content-addressed idempotency, retries
transient failures, and dead-letters permanent failures without persisting raw
errors. Witness replies pass the complete pinned-key signature verification
path. Promotion completion requires an exact target/stage/sequence/statement/
pack receipt from the independently governed target. Transport never signs,
installs, publishes, activates, or bypasses target policy.

Implementation status on 2026-09-29: every Exchange endpoint can now choose
server-authenticated TLS or mutual TLS and optionally pin a custom CA. Client
certificate, private key, and optional key-password values are referenced only
through enabled, unscoped server-side Credential Profiles that permit the
`ecosystem_transport` adapter. The Worker builds a TLS 1.2-or-newer context
with hostname and certificate verification, loads client identity through
Linux `memfd_create` and `/proc/self/fd`, and closes the descriptors without
creating temporary key files. An optimistic `tls_revision` protects complete
identity rotation; stale writers fail closed. Endpoint APIs and audit events
contain references and configuration booleans, never resolved material. Job
success evidence records only the applied revision plus custom-CA and client-
certificate SHA-256 fingerprints. Pending jobs use the current identity at
send time, while signature and exact-receipt verification remain the authority
for the application result. The Exchange Studio page supports endpoint
creation, TLS status, and governed rotation.

Remote catalog and pack-lineage signer rotation are explicit dual-control
operations. A short-lived canonical statement binds the exact catalog sequence
and index digest, or the exact pack predecessor digest, plus the old/new key
fingerprints. Both enabled Ed25519 identities sign it. Acceptance locks and
rechecks current state, persists both signature hashes, and never infers
authority merely because another key is locally trusted. Catalog discovery also
continues checking the historical key that signed its current snapshot.

Accepted ecosystem events enter a transactional transparency chain per
tenant/region namespace.
Catalog snapshots and rotations, pack installs/upgrades, signed revocation
feeds, and uninstalls share a locked monotonic sequence; each canonical record
links the previous digest and advances a checkpoint head in the same transaction
as the governed change. The UI/API recompute the chain from genesis and report
an exact failure sequence. The legacy default namespace retains its original
checkpoint row; independent namespaces have separate log IDs, sequences,
witness policies and scoped record/witness identities. A guarded migration
preserves old rows and refuses downgrade once scoped duplicates exist.

Implementation status on 2026-09-29: the checkpoint now has a stable random log
identity and epoch. `/studio/catalog/transparency/witnesses` pins independent
purpose-scoped Ed25519 witness public keys, publishes bounded canonical
checkpoint offers, verifies short-lived signatures, applies a configurable
live quorum, and exchanges quorum-backed cross-region gossip. Import
revalidates every unique witness and classifies consistent, behind, ahead, or
fork against the local chain; exact document replay is idempotent and fork
evidence is durable. Witness operations use the audit ledger without advancing
the chain they attest. Automated credential-backed checkpoint delivery is
implemented, including optional outbound mTLS workload identity and
certificate rotation. Independently deployed witness services, automated
gossip, and partition/recovery acceptance remain production gates. Verified
fork evidence now atomically creates a mandatory critical Alert, deduplicates
the same conflicting head across regional observations, enters the ordinary
Situation/Workflow alert paths, and retains a durable observation-to-Alert
link. A bounded administrator reconciliation route backfills historical fork
rows without links.

Implementation status on 2026-09-29: Collector Studio accepts local OpenAPI
3.0/3.1 JSON and YAML. The author selects one exact read-only GET `operationId`;
the platform never fetches the specification, rejects external references and
write operations, bounds document/path/reference/schema complexity, and uses a
successful JSON example or deterministic schema synthesis to create the same
secret-checked fixture contract. Only the selected operation summary, minimized
sample, and SHA-256 provenance enter the session, Artifact, and model context.
The full document and unrelated operations are not retained. YAML decoding is
size/event/depth bounded and rejects aliases, anchors, duplicate keys, unsafe
tags, and multiple documents.

Implementation status on 2026-09-29: non-MIB Collector sessions can also attach
one plain-text, Markdown, or reStructuredText API/vendor document as design
context. UTF-8 size, line count, and line length are bounded; private keys,
unsupported control/format characters, and invalid metadata fail closed.
Recognized secret literals and credential assignments are redacted before the
sanitized context is stored or sent to the model. The public session, audit,
and immutable Artifact projections contain only media type, SHA-256, byte
counts, and redaction count. The system prompt labels the context untrusted,
while the deterministic compiler still permits only fields present in the
sample and retains the ordinary schema, sandbox, and human-publication gates.
MIB input cannot combine with this context because its minimized symbol catalog
has a separate trust and attestation boundary.

Implementation status on 2026-09-29: Collector Studio also accepts sanitized
JSON output from a platform-owned fixed read-only SSH command profile. The user
selects the profile and target host/port but cannot submit command text. The
Artifact pins the profile with a JSON Schema constant and uses the same
network-denied generated transform sandbox. Runtime requires a scoped
credential profile, Worker target allowlist, explicit OpenSSH `known_hosts`
file, and bounded strict JSON; implicit SSH keys/agent, keyboard-interactive
authentication, duplicate JSON keys, scalar roots, and host-key bypass all fail
closed.

Implementation status on 2026-09-29: Collector Studio now accepts one bounded
SMI MIB as a proposal-only input. A trusted subset parser strips comments,
discards descriptions/raw text, bounds symbols/OID arcs, and persists only the
source hash plus locally resolved name/kind/numeric-OID/syntax/access/index
catalog. The model can select only catalog names; platform code deterministically
maps them back to numeric OIDs and creates an
`icheck.snmp-exporter-proposal/v1` Artifact. Its external-generator gate is
unsatisfied and immutable publication is blocked in both UI and service code.
Generator compilation, module installation, bounded live walk/cardinality
validation, and creation of a new attested deployable version remain an
explicit production/lab gate for every proposed module.

Implementation status on 2026-09-29: the receiving side and the separate
one-shot attestor runner for that production gate are now implemented. A
dedicated Ed25519 `snmp_exporter_attestation` trust purpose
signs the exact proposal/MIB/module hashes, generator and exporter binary hashes,
identical generated/installed configuration hashes, bounded zero-timeout live-
scrape evidence, expiry, and a one-time nonce. Verification writes an immutable
attestation ledger and creates a separate validated
`icheck.snmp-exporter-attested/v1` version. Direct Artifact publication is still
denied; only a passed iCheck Collector canary can promote it, with attestor-key
revocation and evidence expiry rechecked atomically. A read-only API exports the
exact proposal input; the runner re-parses the staged MIB, invokes a pinned
upstream generator without a shell, proves installed-module equality, performs
allowlisted live scrapes, minimizes evidence, and signs an atomically written
envelope. A hardened non-container systemd template is included. Installing the
generator, provisioning the OS identity/key, separately installing the reviewed
module, and completing the real-device lab run remain open.

Implementation status on 2026-09-21: Capability Studio also authors governed
`icheck.workflow/v1` templates from conversation and the live Tool Registry.
The product compiler stores typed nodes, input bindings, graph transitions,
budgets, permission union, and tool dependency hashes. Deterministic validation
proves that every node is reachable and can terminate, cycles contain a bounded
read-only agent loop, and every state-changing path is statically dominated by
approval and followed by a read-only post-check with a real rollback branch.
The UI previews the graph beside the conversation. This initial slice covered
template authoring and publication; the durable runtime and scheduling boundary
are recorded in the 2026-09-25 update below.

Implementation status on 2026-09-21: Capability Studio also authors governed
`icheck.topology/v1` views. The model sees only aggregate inventory counts,
device kinds, and sites, then proposes a typed selector/layout contract. The
platform resolves device and endpoint nodes plus current wired, wireless, and
IP relationships, enforces hard preview bounds, and excludes endpoint usernames
and raw vendor payloads. `/studio` renders the graph before explicit human
publication and refinements produce immutable versions. This began as
point-in-time view authoring. The later 2026-09-25 update adds published live
current-state rendering; device-to-device LLDP/CDP packs were still open at
that point and are superseded by the 2026-09-28 adjacency update below.

Implementation status on 2026-09-25: published `icheck.topology/v1` Artifacts
now run at `/topology` rather than stopping at a Studio preview. Discovery
returns only the current published version. Every render revalidates the
canonical immutable contract and publication provenance, resolves current
device, endpoint, and generic Entity/Relationship state, and enforces
`assets.read` plus device/site SQL scope for every node and relationship query.
Responses are bounded to the declared contract limits, omit arbitrary graph
attributes and raw payloads, and return an authorized empty graph without
revealing out-of-scope inventory. The dedicated operator page shows version and
content-hash provenance, scope state, search, safe node identity, layout, and
truncation/drift/empty states. Temporal topology replay, vendor-specific
adjacency mappings, and Investigation-generated topology proposals were still
open at that point; later updates below close the first adjacency/proposal
slices.

Implementation status on 2026-09-30: Capability Studio now also authors the
first non-topology visualization Artifact, `icheck.visualization/v1`. The model
sees only a bounded safe catalog of enabled governed service indicators and may
select exact service/indicator pairs for line, stat, or status panels with
fixed layout, refresh, lookback, and point budgets. It cannot emit PromQL, SQL,
JavaScript, source queries, URLs, credentials, or executable rendering code.
Trusted code validates selectors, creates a minimized historical preview, and
uses the ordinary immutable validation and human-publication lifecycle. The
published `/visualizations` runtime requires `services.read`, hides any view
whose complete referenced service set is not in caller scope, revalidates the
canonical contract on every render, and exposes only observation time/value,
measurement quality, and derived threshold state. Source references,
dimensions, evidence URLs, actors, contacts, components, and raw telemetry are
omitted. Missing, retired, or disabled dependencies become explicit drift
states. Arbitrary query authoring, cross-source panels, and report types beyond
deterministic service-health snapshots remain future governed slices.

Implementation status on 2026-09-30: Capability Studio now authors the first
Report Artifact, `icheck.service-health-report/v1`. The model sees the bounded
safe indicator catalog and selects exact indicators plus a title, lookback, and
sample cap. Trusted code produces current/minimum/maximum/average/trend and
threshold/freshness summaries without model prose, queries, raw time series,
labels, dimensions, source references, contacts, or credentials. The published
`/reports` runtime requires `services.read`, hides partially visible reports,
revalidates immutable provenance, resolves current normalized observations,
and exposes explicit no-data, truncation, and dependency-drift state.

Implementation status updated 2026-10-02: reports now support application-immutable,
retained generated instances and authenticated PDF/HTML/CSV/JSON downloads.
Fresh capture pins an exact published version with principal/namespace-bound
idempotency, original generation time, minimized observations and canonical
snapshot digest. Read/export revalidate that digest, the source version hash,
service membership and current ownership; deprecated versions remain historical
data without renewed execution authority. Scoped keyset history and verified
downloads live in `/reports`, not the operator home. Renderers are fixed trusted
code, with escaped labels, CSV formula protection, bounded output and packaged
Chinese-capable PDF fonts; AI cannot emit executable document templates.
Snapshot and exported-byte hashes are distinct. Exports are not delivery proof.
Retention is indefinite/no automatic pruning. Namespace-local storage limits
can now bound instance count and canonical snapshot bytes through a revisioned
admin API; capture serializes admission and accounting with the saved instance.
Locked policy reads refresh cached counters, limits and revision; PostgreSQL
quota mutations require atomic `READ COMMITTED` transactions with DBAPI
autocommit disabled. Commit-enabled retries release their accounting locks.
Local `reports.list_saved` and
`reports.get_saved` Agent Tools expose bounded, cited numeric historical
snapshot evidence, and recheck current service ownership even when replaying a
persisted Tool result. A separate retention page now governs digest-pinned
operator archive acknowledgements, legal holds and independently reviewed purge.
Active holds, Agent evidence and exact-instance delivery receipts block purge;
execution rechecks references and atomically reclaims quota while retaining a
tombstone. Archive acknowledgements remain operator assertions. Separate
verification receipts now require actual HTTPS retrieval and hashing of the
complete snapshot-plus-document archive. New purge requests bind that receipt,
and execution refetches the exact external object before locking/rechecking and
deleting local bytes. Source/credential bindings are namespace-local and
revisioned; legacy assertion-only approvals cannot execute. This proves bytes
observed at that source/time, not physical storage independence or WORM policy.
The report database lifecycle passed real PostgreSQL contention, non-owner
tenant/region RLS, stale policy/review-state rejection, late Evidence FK
protection, bounded transaction-loss/retry, data-bearing quota backfill and
native logical backup/restore on 2026-10-03. Restored document bytes, hashes,
quota and purge/approval/archive history remain intact. The archive bytes in
these tests are controlled fixtures; this does not accept live HTTPS/Vault,
WORM, independent durability, production upgrade datasets, backup policy,
PITR/HA or representative capacity.
Policy-driven expiry, live archive gateway/storage acceptance, live vendor
attachment acceptance, arbitrary calculations and cross-source reports remain
later gates.
Service keys, Artifact kind/name identities, and signed capability-pack
name/version/digest identities now use tenant/region-local uniqueness with a
legacy-row-preserving Alembic migration and guarded downgrade. See
`docs/service-health-reports.md` for exact contracts and verification limits.

Saved-document scheduled delivery now stores a bounded PDF/HTML/CSV/JSON
document with its exact snapshot. The Workflow sees a digest-pinned manifest;
an MCP adapter retrieves the original bytes with its own authorized identity.
Both send and post-check must confirm that document digest. Pending evidence
and verified receipts protect the instance/document, with independent document
quota accounting and transactional purge reclaim. Receipt export v2 pins the
document identity; existing numeric exports retain v1 digest material. The
in-product Workflow designer receives the manifest schema. Live vendor and
PostgreSQL acceptance remain open; see `docs/report-attachment-delivery.md`.

Implementation status on 2026-09-30: schedule-triggered Workflows may now bind
one exact published canonical service-health Report version to one typed input
key. Static input cannot override that key. Activation and every occurrence
recheck Report publication/provenance, run-as `services.read` permission and
complete service scope, canonical contract, combined input schema, and current
Workflow Tool dependencies before generating a fresh minimized snapshot. The
input must bind directly to a pinned state-changing MCP Tool, so graph
validation preserves a dominating approval, read-only post-check, and attached
rollback. Outbox idempotency/retry is unchanged; failures retain only type and
hash and occur before Investigation creation. Capability-pack revocation or
uninstall disables schedules referencing an affected Workflow or Report
version. `/studio/workflows` exposes the exact binding; vendor delivery and
credentials remain in the separately governed MCP adapter.

Implementation status on 2026-09-30: report delivery now has a first-class
immutable receipt ledger. Activation infers exactly one primary change
Tool/argument and validates required `delivery_id` plus optional safe URL/status
paths against the pinned MCP output schema. The terminal Investigation
checkpoint atomically requires exactly one successful producer call, proves its
argument equals the generated report, rechecks exact Workflow/Report hashes,
and records occurrence, Investigation, ToolCall, provider and delivery fields.
Missing/duplicate calls, unsafe URLs, result-path drift, report tampering, or
replay conflicts roll back completed status. Operations APIs and
`/studio/workflows` expose receipts; audit retains only the external ID hash.

Verification hardening on 2026-09-30: a completed Workflow may also represent
a failed delivery followed by rollback. Receipt creation therefore now requires
validated producer-node and subsequent post-check execution checkpoints, exact
approved action evidence, result hashes, chronological order, and both calls in
the terminal evidence trail. Failure or rollback terminates without a receipt;
unproven completion fails closed. Local and database-free Agent runtimes retain
only minimized call IDs/statuses in these checkpoints. Receipts now pin both
delivery and verification ToolCalls/times. Older receipts retain null proof
fields and are visibly unverified rather than retroactively upgraded.

The first portable receipt export is authenticated, namespace-bound,
`icheck.report-delivery-receipt/v1` JSON with UTC timestamps and a reproducible
content digest, excluding report bodies, raw Tool results and credentials.
It does not claim provider signatures. Delivery receipts remain indefinitely
without automatic pruning. Saved-report retention separately supports explicit
archive acknowledgement, legal hold and reviewed purge, but live schedule
receipts currently pin a Report version rather than a saved snapshot. The Web UI distinguishes Investigation
dispatch from verified delivery and offers JSON download. A forward migration
also repairs tenant/region columns and PostgreSQL RLS on the three recently
added receipt/visualization-proposal tables using parent Investigation scope.
The occurrence API/UI project pending approval and terminal execution without
verified delivery separately; a dispatched or completed Investigation never
implicitly becomes a provider-confirmed delivery claim.

Implementation status on 2026-09-30: a bounded Investigation may request
`icheck.visualization-proposal/v1`. Completion verifies cited evidence belongs
to the Investigation, validates exact indicator selectors under the frozen
Investigation authorization scope, requires current normalized observation
evidence, and persists a separate minimized proposal rather than an Artifact.
The dedicated `/studio/visualization-proposals` page requires a reasoned global
human publish or reject decision. Publish atomically creates, revalidates, and
publishes an ordinary immutable Visualization Artifact; failure rolls back the
entire transaction. Runtime reads still apply the current caller scope.

Implementation status on 2026-09-28: a bounded Investigation may request
`icheck.topology-proposal/v1`. Completion fails closed on missing or foreign
evidence, validates the declarative spec and preview under the Investigation's
frozen authorization scope, and persists a separate AI proposal. The dedicated
`/studio/proposals` review page never activates the proposal directly. A
reasoned global human publish atomically creates, validates, and publishes the
ordinary immutable Topology Artifact; rejection creates no Artifact.

Implementation status on 2026-09-28: the seeded
`builtin-snmp-device-adjacency` Artifact and trusted `snmp_topology` Worker
adapter now convert a reviewed SNMP Exporter LLDP/CDP info metric into the
strict `icheck.network.device-adjacency-snapshot/v1` contract. A healthy
complete snapshot creates scoped `network.device` entities and undirected
`network.l2_neighbor.lldp` or `network.l2_neighbor.cdp` relationships,
aggregates bounded parallel ports, closes missing links only on newer data, and
prevents delayed snapshots from reactivating stale topology. Those active
relationships flow through the existing published Topology and Situation
impact paths. Exporter/target allowlists and exporter-held SNMP secrets remain
unchanged. The contract is vendor-neutral; multi-capability web activation is
implemented, while vendor MIB/generator mappings and live-lab compatibility remain explicit
acceptance gates rather than assumed support.

Implementation status on 2026-09-22: Capability Studio also authors
`icheck.tool/v1` MCP contracts and `icheck.skill/v1` diagnostic skills. Tool
contracts contain strict schemas, exact fixtures, permissions, risk, approval,
timeout, and result-size limits; validation executes both fixture schemas and
publication deliberately does not register or activate the external tool.
Diagnostic skills may compose only enabled read-only Tool Registry entries and
pin their durable IDs, schema hashes, permissions, and limits alongside hard
agent budgets, evidence requirements, success criteria, and escalation rules.
Platform policy outranks generated instructions. Implementation status on
2026-09-24: a stateless MCP `2026-07-28` gateway now registers allowlisted
servers, checks health, attests live input/output schemas against published Tool
versions, records reasoned activation/deactivation, and binds active contracts
to the Tool Registry. The leased Agent Worker resolves credential references,
validates arguments and structured results, redacts returned secrets, persists
hash-addressed evidence, and reuses the existing four-eyes interrupt before a
change tool reaches the remote server. At that point, dedicated attestor
workers, OAuth, signed MCP distribution/catalogs, and canary Tool activation
remained open.

Implementation status on 2026-09-30: MCP HTTP servers may now select OAuth
Authorization Code/PKCE. iCheck consumes RFC 9728 protected-resource metadata,
tries the MCP-mandated RFC 8414/OIDC discovery locations, pins the exact issuer
and canonical MCP resource, validates RFC 9207 `iss` before code redemption,
and includes RFC 8707 `resource` in authorization and token requests. Bearer
challenge scopes are authoritative within an administrator-defined upper bound.
Pre-registered and Client ID Metadata Document client IDs are supported;
deprecated Dynamic Client Registration is deliberately absent. Access and
refresh tokens are CAS-written to Vault KV v2 and resolved/refreshed by the
leased Agent Worker, never persisted in control-plane tables or LangGraph
state. Revocation blocks execution before deleting the Vault bundle. At that
point, runtime 403 step-up authorization, live external-provider acceptance,
signed MCP distribution/catalogs, and canary Tool activation remained open.

Implementation status on 2026-09-30: MCP contract verification now runs as a
durable, asynchronous job on a dedicated database-free attestor Worker. A
separate bootstrap trust boundary grants only the reserved `mcp_attestation`
capability and `mcp_attestor` role; subsequent claims and completion require the
Worker Bearer token plus the configured mTLS identity. The Worker receives a
lease-bound credential reference, resolves Vault locally, performs bounded
`tools/list`, and returns hashes rather than secrets. Jobs pin the exact server,
published Artifact, contract/schema hashes, and credential-profile revision.
Fresh passed results expire after 15 minutes and activation atomically consumes
one result. Wrong tokens, replay, expired leases, configuration drift, and
ordinary Agent privilege escalation fail closed. `/settings/mcp` exposes queue,
result, and activation as three explicit stages.

Implementation status on 2026-09-30: every new MCP Tool activation now starts
in a deterministic canary cohort. The model-visible catalog and both local and
database-free delegated Agent execution paths independently enforce the cohort
and closed-circuit state. Row-locked success/failure evidence, configurable
budgets, and optimistic revisions gate reasoned human promotion to full
traffic. Budget or consecutive failures open the circuit and disable the Tool
Registry entry immediately. Recovery requires and consumes a fresh attestor
Worker result for the exact current contract, resets health evidence, and
returns the activation to canary. `/settings/mcp` exposes the thresholds,
counters, circuit state, promotion, re-attestation, and recovery controls.
Live external-provider/server acceptance remains open.

Implementation status on 2026-09-30: runtime OAuth 403 scope step-up is now a
first-class governed state machine. Only a bounded Bearer
`insufficient_scope` challenge is propagated from an Agent Worker; raw headers,
provider text, and credentials remain Worker-local. The affected Tool is hidden
from selection and rejected at both execution paths without an automatic
retry, refresh, permission grant, or circuit-budget charge. A namespace-local
ledger merges repeat observations and requires revision-checked human approval.
Scopes outside the configured upper bound require an explicit persistent
allowlist-expansion decision, followed by a separate one-time PKCE transaction.
Provider denial returns the challenge to pending, and only a fresh Vault token
containing every challenged scope resolves it. `/settings/mcp` exposes this
queue beside server runtime state, not on the AI L1 operator home. Live
external-provider/server acceptance remains open.

Implementation status on 2026-09-30: MCP fleet posture is now a complete
namespace-scoped database aggregate with a bounded per-server projection.
`GET /api/v1/mcp/fleet/telemetry` requires global `tools.admin` and reports
server health/freshness, OAuth attention, rollout and circuit state, success
rate, scope-review queues, and attestation backlog/dead letters without
returning raw provider errors or secrets. The `server_limit` parameter caps
only rendered detail; it never changes global totals. `/settings/mcp` places
this exception-first runtime card above its operational ledgers and keeps
configuration controls separate. Opening a circuit emits a deduplicated
critical Alert, and a governed scope challenge emits a deduplicated warning
Alert. Recovery, deactivation, or verified token scope resolves the matching
Alert, so both conditions participate in the existing Situation lifecycle.

Implementation status on 2026-09-22: Artifact governance now includes bounded
semantic version diff, 5 MB `icheck.artifact.bundle/v1` export/import, and
immutable restore candidates. Exported bundles contain the complete portable
contract without validation reports, conversation history, or database child
IDs. Import verifies a canonical bundle digest and source content hash before
creation, then applies secret checks and reruns current target-environment
validation. Restore copies an older healthy contract into a new version,
revalidates it, proves the same content hash, and leaves publication as a
separate human action. Bundle digests alone are integrity checks, not
organization signatures. The updates below add replay, canary promotion, and
the first signed-envelope trust/provenance boundary.

Implementation status on 2026-09-24: `/studio/artifacts` now provides the
dedicated lifecycle surface for immutable version/status inspection, bounded
semantic comparison, local bundle export, verified target import, reasoned
restore candidates, and explicit publication. These controls are deliberately
separate from the AI L1 home and preserve the same server-side authorization,
validation, and audit boundaries.

Implementation status on 2026-09-24: `/studio/replay` now provides immutable
historical golden cases for generated Collectors. Authorized reviewers store
sanitized pre-transform envelopes plus expected envelopes, then execute a
validated, published, or deprecated `python_sandbox_v1` version under the same
Landlock/seccomp boundary used for generated fixtures. The platform persists
bounded counts and hashes, not raw run output or error messages, and reports at
most 50 index-level hash differences. Replay is deliberately separate from
deployment and cannot publish, activate, or promote a version.

Implementation status on 2026-09-24: `/studio/rollouts` now implements the
first bounded Collector canary. A validated polling candidate is attached to a
single scoped shadow deployment and remains claimable only while that rollout
is running. Worker output is schema-checked but never written into the
production evidence stream; only batch hashes, counts, run status, and health
gate results persist. Required healthy runs pass the canary, while configured
failures or deadline expiry automatically disable it. Promotion is a separate
reasoned human action, verifies the original published baseline is unchanged,
and cannot be bypassed through the generic Publish API once canary management
has begun. This promotion changes only the Artifact publication state; the
separate deterministic fleet replacement kernel described next performs the
deployment mutation.

Implementation status on 2026-09-27: canary promotion is now followed by an
optional, separately authorized fleet replacement state machine. Planning
selects deployment records still pinned to the promoted canary's deprecated
baseline, optionally scopes by site/enabled state, validates the published
candidate against every target contract, and persists an immutable canonical
plan hash with per-deployment pre/post fingerprints. Active device-connection
activations are recorded as blocked so this path cannot bypass their preview
and approval fingerprints. Apply and rollback both require the exact plan hash
and a reason, process bounded batches under database locks, defer live Worker
leases/runs, and stop on drift or failures. Rollback touches only successfully
migrated records whose candidate fingerprint is unchanged. Target/configuration
documents and raw errors are excluded from rollout responses and audits; only
IDs, codes, counts, and hashes persist.

Implementation status on 2026-09-29: fleet plans may now opt into strictly
increasing cumulative rollout percentages ending at 100. Planning assigns each
actionable deployment to a deterministic immutable ring. A separate
tenant/region-pinned `icheck-rollout-worker` uses PostgreSQL advisory-lock
leadership, applies only the current ring through the existing hash/drift/lease
kernel, and then stops for a bounded health observation window. Every ring
member must produce the configured number of fresh successful Collector runs;
failed or cancelled runs count against a fail-closed limit. Bounded run
deployment/status/time/count evidence is canonically hashed. Operators can pause,
resume with a fresh evidence window, abort automation to regain manual control,
or separately invoke the existing rollback path. AI output cannot waive these
gates, and the production controller is shipped as an independent hardened
systemd service rather than a Docker-only process.

Implementation status on 2026-09-24: published `icheck.skill/v1` diagnostic
Skills now execute through the existing durable LangGraph Worker path. The AI
L1 home lists published Skills, prepares editable typed input from their schema,
and starts a Skill-bound investigation. Creation validates input, caller
permissions, publication state, and the exact read-only Tool Registry dependency
snapshot; the investigation then pins the version content hash, instructions,
schemas, allowed tools, evidence/termination rules, and dependency metadata.
Effective iteration, tool-call, and token budgets are the stricter of the model
route and Skill contract. The reasoner sees only allowed tools, while the
execution layer independently rechecks that boundary and dependency drift before
each call. Completion requires persisted evidence, output-schema-valid structured
data, and only real evidence references. The structured result is stored and
rendered separately from prose. State-changing Skills remain prohibited and
must use the separately governed Workflow runtime.

Implementation status on 2026-09-25: published `icheck.workflow/v1` versions
now execute as immutable, typed, leased Investigations. Manual launch from the
AI L1 home validates input, caller permissions, publication state, route, and
the exact executable Tool Registry dependency snapshot before atomically
binding and queuing the run. `WorkflowReasoner` advances fixed nodes
deterministically and delegates bounded `agent_loop` nodes to the normal model
reasoner with only their declared read-only tools. Direct, post-check, rollback,
evidence, audit, and state-changing calls use the common runtime; a change still
interrupts on its exact plan and requires four-eyes approval. Workflow limits
cannot enlarge route limits, and dependency drift fails closed.

Implementation status on 2026-09-25: Alert-triggered Workflows require an
explicit exact-version activation separate from publication. Activation pins a
route purpose, service run-as principal, authorization scope, and bounded
Alert-to-input mapping. Each new Alert writes at most one durable trigger event
per activation, and the Agent Worker dispatches the outbox with row locking,
bounded retries, stale recovery, hash-only error metadata, and a unique
event-to-Investigation binding that prevents duplicate runs after process loss.
`/studio/workflows` exposes trigger state and outbox health while manual
Workflow launch remains on the AI L1 home.

Implementation status on 2026-09-27: `icheck.workflow/v1` also supports a
`schedule` trigger whose runtime calendar is activated separately from Artifact
publication. The activation pins a strict five-field cron expression, IANA
timezone, typed static input, route, service run-as identity, authorization
scope, and misfire grace. The Agent Worker locks due schedules and persists one
outbox occurrence per activation plus scheduled UTC instant, advances the next
fire atomically, and skips/counts stale misfires rather than producing an
unbounded backlog. Dispatch has bounded retry and stale recovery, uniquely
binds the occurrence to one Investigation, and rechecks publication, current
identity/scope, input schema, and executable dependency compatibility. Error
state remains type plus hash. `/studio/workflows` exposes activation, next/last
fire, missed-run health, disable, and occurrence attempts. Multi-tenant
scheduler scale acceptance remains open.

Implementation status on 2026-09-30: schedule activations now support a
revisioned exclusion calendar of up to 100 named absolute windows. Windows must
be timezone-aware, non-overlapping half-open intervals, have stable IDs, and
span no more than 366 days. Row locking plus `expected_revision` prevents
concurrent administrators from overwriting calendar changes. When the exact
scheduled UTC instant falls inside a window, the scheduler persists a unique
`skipped/calendar_exclusion` occurrence, increments exclusion health, advances
the next fire atomically, and never dispatches an Investigation. Malformed
persisted state disables the activation with hash-only audit evidence.
`/studio/workflows` exposes creation, revisioned editing, excluded-run health,
and the non-dispatched occurrence ledger.

Implementation status on 2026-09-30: a schedule activation may additionally
pin one exact published `icheck.service-health-report/v1` version and generated
input key. Every occurrence regenerates the deterministic minimized report
under the current run-as scope, validates it against the immutable Workflow
input schema, and requires a direct binding to a pinned state-changing MCP Tool
dependency. Static input cannot spoof the key. Existing approval, post-check,
rollback, exact Tool snapshot, and three-attempt outbox behavior remain in
force; Report publication/provenance/scope/contract drift fails closed before
an Investigation is created. Report package revocation/uninstall disables the
binding and terminally fails pending occurrences.

Implementation status on 2026-09-30: each newly activated Report schedule also
pins a provider key, inferred unique primary MCP Tool/argument, and bounded
Tool-output receipt mapping. Exactly one successful producer-node execution
checkpoint followed by its successful declared post-check, with no executed
rollback, creates a receipt at terminal Workflow completion. It pins both
Artifact hashes, the occurrence, Investigation, delivery/verification ToolCalls
and times. Portable namespace-bound JSON export includes a reproducible digest;
legacy receipts stay explicitly unverified and there is no automatic pruning.
Receipt creation shares the
terminal checkpoint transaction, so malformed, duplicated, unsafe or tampered
delivery evidence prevents completion rather than reporting a false success.

Implementation status on 2026-09-25: portable Artifacts may now use
`icheck.artifact.signed-bundle/v1`. An external signer signs a
domain-separated canonical bundle digest with Ed25519. iCheck registers only
public trust keys, fingerprints them, supports revocation, verifies the
signature before ordinary import, and persists immutable
key/digest/signature/verifier provenance on the target version. Private signing
keys are never accepted or stored. Optional or required signature policy is
configurable; neither a valid signature nor a trusted key bypasses content-hash,
secret, dependency, deterministic validation, or human publication gates.
Purpose-scoped organization trust distribution, dual-controlled root rotation,
externally witnessed delayed emergency root re-anchor, and external
transparency witness quorum/gossip plus durable witness/promotion transport are
implemented together with automated quorum-backed regional gossip. Prebound
enterprise OIDC and source/secret-bound trusted-proxy browser identity are
implemented. Replay-safe CI workload OIDC exchange with prebound service
Principals and short-lived workload-linked tokens is also implemented.
Governed group/role mapping and live IdP/identity-gateway/CI-provider/vendor
recovery-gateway/drill acceptance remain ecosystem work. Verified HSM/KMS
recovery signing, manual atomic promotion publication, and Exchange endpoint
mTLS are implemented.

---

# 33. Credential and Security Model

Credentials must never be directly exposed to the LLM.

Implementation status on 2026-09-29: Credential Profiles hold external
references only and now rotate those references with optimistic revisions and
hash-only audit evidence. Collector and Agent MCP Workers can resolve static
Vault KV v2 values or bounded dynamic Vault leases locally. Dynamic leases are
renewed only inside the owning execution lease, revoked on close, and cleared
from memory; Vault token files are reread for each operation to support atomic
rotation. Lease-scoped dynamic control-plane AI credentials now cover provider
health, LangGraph reasoning, and Capability Studio generation; every request
revokes its Vault lease on success or failure. Cloud secret-manager adapters
remain future provider boundaries.

MCP OAuth adds a dedicated `mcp_oauth_vault` provider. Its bundle holds the
audience-bound access token, optional refresh token, issuer/resource/token
endpoint/client binding, expiry, scopes, and (for a confidential client) its
client secret. Refresh happens inside the Worker immediately before use and
uses KV v2 check-and-set so concurrent Workers cannot silently overwrite a
rotated refresh token. Control-plane tables store only connection state,
expiry, scope, provenance, and hashes.

Architecture:

```text
AI
 ↓
Tool Call
 ↓
Policy Engine
 ↓
Credential Broker
 ↓
Execution Engine
```

Credential types:

```text
SNMP community / SNMPv3
SSH credentials
API tokens
Windows credentials
Cloud credentials
Kubernetes credentials
Database credentials
```

Requirements:

```text
encrypted at rest
RBAC
secret rotation
audit
least privilege
credential scopes
```

## 33.1 AI Provider and Model Configuration

The platform must be provider-neutral and allow administrators to configure AI
without changing application code.

Configuration objects:

```text
AIProvider
  type
  base_url
  authentication_type
  secret_reference
  network and data-residency policy

AIModel
  provider
  model_name
  capabilities
  context limit
  cost and latency class

ModelRoutingPolicy
  task class
  primary model
  fallback models
  privacy boundary

AgentProfile
  role and instructions
  model policy
  tool policy
  maximum iterations
  wall-clock and cost budget
  approval and escalation policy
```

Tokens and infrastructure credentials must never be stored as plaintext model
configuration or returned to the browser. The database stores an opaque secret
reference; a credential broker resolves it only at execution time. The settings
page must support a redacted connection test and must prevent secrets from
entering prompts, traces, tool outputs, or logs.

Implementation status on 2026-09-29: `AIProvider`, `AIModel`, and bounded
`ModelRoutingPolicy` foundations are implemented with outbound host allowlists,
environment and control-plane Vault KV v2 secret references, redacted
model-list tests, audit, API, and a dedicated settings page. Vault configuration
uses a process-local token file, rejects redirects and unsafe URLs, returns only
one selected value, and never exposes that value through the GUI or database.
The first OpenAI-compatible inference adapter and
bounded LangGraph investigation kernel are also implemented: structured model
decisions, typed read-only tools, immutable product checkpoints, evidence and
tool-call persistence, budget/duplicate guards, and deterministic escalation.
`AgentProfile` is now implemented as revisioned policy with role/escalation
instructions, permission-scoped Registry or exact Tool allowlist, provider
privacy tier and data-residency placement gates, model cost classes, and
iteration/Tool/time/token ceilings. Each Investigation freezes the policy and
intersects its budgets with the selected route; revision, disable, or placement
drift fails closed before model invocation. The administration surface is
separate at `/settings/agents`. Dynamic Vault leases/rotation, cloud
KMS/secret-manager providers, contractual/live residency validation,
live-provider fallback acceptance, and live PostgreSQL resume acceptance remain
future work. Ordered, snapshotted, audited model
fallback, durable asynchronous execution, governed action approval, and the
initial AI operator workspace are implemented. This is a working kernel and
first product surface, not a completed AI operator product.

---

# 34. Audit

Every AI tool invocation should generate an audit record.

Example:

```text
timestamp
user
agent
tool
target
parameters
execution engine
result
duration
risk level
change_id
reviewer
approval status
```

This is mandatory for commercial production environments.

---

# 35. Suggested Technology Stack

## Backend

```text
Python
FastAPI
Pydantic
SQLAlchemy
Celery / Temporal / task engine
```

## AI / Agent

```text
LangGraph as the initial stateful orchestration runtime
provider-neutral model adapters
MCP client and gateways at extension boundaries
typed Python tools and internal capability APIs
```

## CMDB / Knowledge

```text
PostgreSQL
```

Possible future addition:

```text
Graph database if relationship traversal becomes difficult
```

Do not add a graph database prematurely.

---

## Metrics

```text
Prometheus
SNMP Exporter
VictoriaMetrics / Mimir / Thanos
```

## Logs / Events

```text
OpenTelemetry Collector
Loki / OpenSearch / ClickHouse
```

## Management

```text
Ansible
Ansible Runner
Nornir
Netmiko
NETCONF
gNMI
REST APIs
PowerShell
PSRP / WinRM
WMI / CIM
```

## Cache / Queue

```text
Redis
Kafka / Redpanda if required by scale
```

## Frontend

```text
React
TypeScript
WebSocket / SSE
Topology visualization library
```

## Production Deployment

```text
Development/demo:
  Docker Compose may package PostgreSQL, API, and frontend.

Production baseline:
  HA control-plane services on VMs or bare metal
  installed Python wheel with bundled operator-only migrations
  standalone Node.js frontend on loopback behind trusted TLS ingress
  tenant/region-pinned systemd regional/site collectors and execution workers
  PostgreSQL HA for knowledge, configuration, audit, and workflow state
  PostgreSQL RLS with non-owner API/Worker roles
  separately owner-provisioned LangGraph checkpoints verified without runtime DDL
  backup restore into an isolated database before runtime rollout acceptance
  Prometheus-compatible regional collection with federation or remote write
  recommendation-only regional scaling controller plus an independently
  privileged, allowlisted, drain-safe systemd process capacity provider
  external secret management
  queue-backed scheduling, leases, rate limits, and backpressure

Optional:
  Containers or Kubernetes where the operator already standardizes on them
```

Containers are a deployment choice, not a scalability strategy or a requirement.
Collector and execution processes must remain independently deployable and
horizontally scalable.

The native frontend package includes its server, traced dependencies and assets;
API traffic is routed directly by the trusted ingress. Browser builds never hold
AI tokens or device credentials. `icheck-db` reads/applies the wheel's bundled
migrations without a checkout, requires an explicit database URL, and requires
operator acknowledgement of backup and coordinated drain before upgrade. Existing
migration guards remain authoritative. See [native release](docs/native-release.md)
and [lab acceptance](docs/lab-acceptance.md); package startup alone is not demo
or production acceptance.

The browser operator workspace treats a session or tenant/region change as a
data boundary: in-flight reads and mutations retain their original context,
old responses are rejected, and storage is checked before a new request even
when a cross-tab change event is still pending. Other tabs reload or navigate
to clear rendered data. Enterprise login completion verifies the new session
before opening the
workspace. The controlled browser acceptance (private development evidence; not distributed)
checks this behavior locally; production identity, accessibility and live-device
acceptance remain separate.

The live investigation EventSource carries the selected namespace and rejects
events after a session or scope change, including the interval before a
cross-tab storage event is delivered. Open streams are closed on invalidation;
server-side authorization remains authoritative.

The current local native code gate accounts for 1,643 PostgreSQL and 1,853
ordinary test nodes with terminal passes across resumed runs. The installed
candidate also passes restricted-role reads, owner-only migration/checkpoint
provisioning, four fresh required-auth API lifespans and isolated logical restore
from a clean Linux environment with 72 pinned core/Windows dependencies. See
native database acceptance (private development evidence; not distributed).
This is not actual TLS, systemd/multi-host restart, Windows connectivity,
production capacity or the GUI-onboarded live lab; those gates still precede
the integrated demo.

---

# 36. Recommended Execution Strategy

Use a preference model.

## Read / Diagnostic Operations

```text
Native structured API
      ↓
gNMI / REST / NETCONF
      ↓
Nornir
      ↓
Netmiko
      ↓
raw SSH CLI
```

## State-Changing Operations

```text
AI
 ↓
Change Request
 ↓
Peer Review
 ↓
Approval
 ↓
Ansible
 ↓
Structured vendor module / API
 ↓
Infrastructure
```

Exceptions are allowed when a vendor has a better native API.

---

# 37. AI Capability Studio and Artifact Architecture

Capability Studio lets an engineer create and iterate capabilities in conversation.
Replace its seven-designer front page with a simple library and one guided
builder. MCP packages use **describe → AI generates and validates → approve and
install → use**. Monitoring activation retains its target checks. Starting actions are Monitor a
device or API, Build a dashboard, and Automate a check. The AI selects the
artifact kind; the engineer should not need to understand internal registries.

The landing page is the categorized library, with collectors, MCP servers,
function tools, workflows/Skills and other capabilities. Creation, saved
conversations, version history and MCP setup are separate pages. One generated
MCP package owns multiple tools and one installation identity across revisions.
Show tools nested under that server, with installation state independent of
validation. Unvalidated attempts remain in a separate draft/history area; never
present a failed authoring attempt as an additional installed server.

MCP installation is package-wide and does not require selecting or testing devices.
The platform packages, validates and checks startup/discovery automatically, then
registers every tool after one human approval. At invocation, resolve devices from
inventory under the installed policy intersected with the caller's current access.
Do not enumerate fleet devices in installation records. Shared credentials and
access profiles belong to Assets, not each MCP server. Keep optional tests, source
and lifecycle diagnostics off the default approval path. HTTP and firewall adapters
must use this same package lifecycle, not inherit a Netmiko setup wizard.

Monitoring presents one managed device/service per identity with nested collection
checks. Counts, categories and pagination are resource-based. SSH is management
access, never an extra monitored resource. A resource without configured checks
is not monitored, not implicitly healthy.

Reuse saved credentials during runtime target resolution. SSH first-use identity review
displays a device fingerprint for explicit confirmation in the product, remembers
that choice and requires renewed review on changes. Discovery performs only a
bounded key exchange, not authentication; an observed first-use key is never
automatically trusted. Exact saved-key verification remains mandatory on tool
connections. An unset physical site inherits the selected credential's connection
scope, without silently moving the device or altering its existing monitoring
connection. The confirmed public identity uses the existing connection storage;
it is not a second credential store or a new monitoring collector.

Legacy SSH is a per-device compatibility capability, not a fleet downgrade.
The native MCP path exposes a named, versioned profile (`legacy_cisco_v1`) with
explicit human risk acceptance, audit history and exact device/connection/IP/port/
identity binding. Modern SSH is the default. Legacy mode supports group14/SHA1,
RSA/SHA1, AES-CBC and HMAC-SHA1, prefers modern negotiation and never bypasses
host-key verification or automatically falls back. Group1, DSA, 3DES and MD5 are
outside this profile. Profile changes invalidate frozen execution bindings;
reusable installations resolve the current profile on the next call. Target
identity changes require renewed trust review. Reuse the same policy for native
fingerprint discovery and Netmiko tools. Keep exceptions outside generated code,
model authority, reusable credentials and system-wide SSH configuration.

```text
User Requirement
      ↓
AI determines artifact type and asks only for missing operational facts
      ↓
Generate:
- typed contract and metadata
- implementation or declarative definition
- entity / relationship / observation mappings
- permissions and risk classification
- dependencies and secret references
- tests, fixtures, health checks, and documentation
      ↓
Deterministic Validation
      ↓
Isolated Sandbox Test
      ↓
Interactive Preview
      ↓
Policy / Security / Human Approval
      ↓
Publish Immutable Version to Artifact Registry
      ↓
Canary or Scoped Deployment
      ↓
Runtime Health, Audit, Rollback, and Conversational Iteration
```

The same lifecycle applies to collectors, parsers, Grafana dashboard/topology
templates, tools, Skills and workflows. Dashboard definitions use Grafana's
supported panels; no new iCheck metric visualization runtime is developed.
Published artifacts become discoverable capabilities for authorized agents.

The default UI shows purpose, target, expected metrics or outcome, interval,
credential reference, test result and one clear next action. It must distinguish
a tested draft from installed collection and fresh observed data. Advanced
details contain:

- The generated contract or code alongside the conversation when requested.
- Test fixtures, sandbox results, generated evidence, and errors.
- Semantic diffs between artifact versions.
- Dependency and permission impact.
- Runtime dependency, permission, provenance and execution-blocker detail.
- Draft, test, review, published, deprecated, and rolled-back states.
- A one-click path from a failed runtime execution back into an AI-assisted edit.

Existing backend capability to reuse: the first governed form of this path is available for
failed Collector runs, failed Artifact replays, and failed Skill/Workflow agent
executions. It binds the exact failing Artifact version, carries only bounded
counts/codes and evidence hashes into an idempotent Studio revision, excludes
raw operational data, and preserves all normal validation and publication
gates. Additional runtime types can join through the same typed evidence
contract.

Generated artifacts must be portable and exportable. iCheck must not lock the
user's operational knowledge inside an opaque conversation history.

---

# 38. Agent Runtime and Orchestration

LangGraph is the recommended stateful orchestration runtime for the first
implementation. Model providers, tool implementations, and artifact formats must
remain replaceable behind iCheck-owned interfaces.

## 38.1 Hybrid Workflow Model

Known runbooks should use deterministic graphs. Open-ended troubleshooting
should use a bounded agent loop. A single investigation may combine both:

```text
Purpose / Alert
      ↓
Scope and impact
      ↓
Load entity, topology, history, and current evidence
      ↓
Plan next diagnostic step
      ↓
Policy and tool eligibility check
      ↓
Execute tool(s)
      ↓
Normalize and persist evidence
      ↓
Evaluate hypotheses
      ├── evidence sufficient ──────────────→ explain / recommend
      ├── more evidence needed + budget ───→ plan next step
      ├── risky action required ────────────→ human interrupt
      └── budget exhausted / low confidence → escalate to L2
                                              ↓
                                  approved action / validation / rollback
```

The persisted investigation state should include:

```text
purpose and initiating event
entity and service scope
observations and evidence references
hypotheses and confidence
tool calls and normalized results
iteration, time, token, and tool-cost budgets
pending approval
conclusion, recommendation, and escalation reason
```

Every loop is bounded by maximum iterations, wall time, tool cost, duplicate-call
detection, target rate limits, tool allowlists, and evidence-based stop rules.
Checkpointing must allow investigations to survive process restarts. Human
approval must pause and resume the same durable investigation.

## 38.2 Tool and MCP Strategy

Not every tool should be a separate MCP server.

```text
Core low-latency capability       → typed in-process tool or internal API
Distributed collection/execution → HTTP or gRPC worker contract
High-frequency telemetry         → exporter / collector / remote-write protocol
External or user plug-in boundary→ MCP server or gateway
```

MCP is an interoperability boundary for focused capability packs, third-party
integrations, and user extensions. Tools should be grouped by security and
operational domain rather than creating one server per function. The iCheck host
retains model context, policy, consent, credentials, audit, and cross-tool
orchestration.

## 38.3 Initial Agents

```text
Supervisor Agent
Network Agent
Systems Agent
Application / Kubernetes Agent
```

Start with these roles and split into Windows, Linux, virtualization, storage,
database, or vendor specialists only when evidence shows that separate context,
permissions, or tools are necessary. Specialized agents are subgraphs or tools
under the supervisor, not independent opaque control planes.

## 38.4 Current Kernel Contract

Implementation status on 2026-09-29:

- LangGraph owns the executable reason → tools → reason state machine and may
  use its PostgreSQL saver for thread-level restart recovery.
- iCheck separately persists immutable, hash-addressed product checkpoints,
  evidence references, tool calls, conclusions, confidence, uncertainty, and
  escalation. LangGraph storage is not exposed as the product audit model.
- The OpenAI-compatible reasoner reads only the configured provider, model, and
  server-side credential reference. Provider tokens, infrastructure credential
  references, and device connection configuration are excluded from prompts.
- Each investigation snapshots its authenticated principal, permissions, and
  authorization scope. The model receives only currently executable internal
  tools allowed by that immutable snapshot. Persistence and execution enforce
  the permission again; tool results remain untrusted evidence.
- Human operator routes use persistent RBAC and device/site scope. Endpoint IP,
  attachment, and wireless child records are minimized to the same scope.
  Built-in tools apply the immutable investigation scope at execution time.
- Principals are fixed to one tenant and may select only enabled assigned
  regions. ORM criteria, write guards, transaction-restored PostgreSQL RLS,
  namespace-local configuration keys, and region-pinned Workers enforce that
  boundary. Production database roles must be non-owner and lack `BYPASSRLS`.
- Publisher trust is accepted independently in each tenant and region. Public
  key fingerprints, trust-domain organization IDs and remote catalog URLs may
  repeat across namespaces, but their pins, purposes, validity, revocations,
  source heads and receipt histories are distinct. Signature, trustee,
  discovery and quarantine paths must never borrow another namespace's trust.
  A shared platform trust domain is not implicitly enabled.
- Browsers use a hash-only, revocable HttpOnly session; unsafe cookie requests
  require a rotating CSRF token. Username/password is the default human GUI
  sign-in, using existing Principal subjects as usernames and separately salted,
  versioned PBKDF2-HMAC-SHA-256 password hashes. Global identity administrators
  provision/reset human passwords; users change their own password with the
  current password. SQL-backed failed-login lockout is shared across API workers.
  Password changes revoke browser sessions without modifying API or worker
  credentials. Tokens remain API/Collector mechanisms; the GUI has no token
  input. Legacy programmatic token-to-cookie exchange is disabled by default.
  Local user password hashes are distinct from infrastructure/model secrets,
  which continue to use external secret references. See `docs/control-plane-auth.md`
  for provisioning, tenant selection and session rules.
  The existing evaluation host deployed this login design on 2026-10-11 as
  r7 with SQL head `p3t5v7x9z1c4`; its same administrator, API credentials and
  worker identities were preserved. Verified HTTPS password/session/CSRF/logout
  checks are recorded in
  `acceptance/engineering-preview-v01-password-login-deployment-2026-10-11.json`.
  This host upgrade does not establish production or fleet-scale qualification.
  Prebound enterprise OIDC Authorization Code/PKCE
  federation now creates the same session without letting provider claims or
  groups grant local roles. The separate trusted-proxy adapter creates the same
  session only when a raw allowlisted ingress peer, a root-provisioned
  shared-secret file, and a hash-only prebound external subject all match. It
  persists a success/denial ledger without raw subjects or proxy secrets.
  Tenant administrators can inspect redacted session metadata, revoke one or
  every session for a Principal with reason-hash audit, and identity disable
  serializes against federation login before atomically revoking every linked
  OIDC or trusted-proxy session.
- `/settings/identity` is the dedicated administration surface for Principal,
  role/scope, access-token, federated-binding, and browser-session lifecycle;
  those controls do not add another dashboard to the AI L1 home. Principal
  disablement atomically revokes all active tokens and sessions, enablement
  never revives them, role revocation changes authorization on the next
  request, and self-disable/self-binding-revocation fail closed.
- CI automation exchanges a freshly signed, allowlisted OIDC/JWT assertion for
  a short-lived icw_ token. Exact issuer, audience, and subject hashes bind one
  service Principal; unique jti consumption blocks replay; token expiry is
  bounded by both assertion and local policy; disabling the identity is checked
  again on every authenticated API request.
- Core low-latency tools remain typed internal handlers. External/user tools
  cross the governed MCP gateway only after an immutable published contract is
  exactly matched to live `tools/list` schemas and separately activated.
  Runtime permission, Worker lease/capability, credentials, schemas, size,
  evidence, and approval are rechecked independently of model choice.
- A state-changing tool creates an exact-plan proposal and durably interrupts
  the same LangGraph thread before execution. A different principal with
  `changes.approve` must decide the matching plan hash. The existing execution
  is requeued and resumes the same checkpoint; an ambiguous `executing` action
  after worker loss is never automatically replayed.

The direct graph service entry point runs only a fresh investigation and rejects
partially consumed state. The leased agent worker chooses fresh execution or
resumes the existing LangGraph thread, renews ownership per node, observes
cancellation, emits ordered/SSE progress, and reconciles a terminal graph commit
after worker loss. The AI L1 home creates these durable investigations and shows
their trace, evidence, conclusion, confidence, uncertainty, and real collection
gaps without moving terminal inventory onto home. Controlled tests cover graph
reconstruction and resume with an in-memory saver; frontend lint and production
build cover the workspace. On 3 October 2026 an isolated PostgreSQL
[graph process-loss probe](./acceptance/langgraph/reports/2026-10-03-private-postgresql-recovery.json)
passed after `SIGKILL` and same-thread resume. A separate
[database-free Agent Worker takeover probe](./acceptance/langgraph/reports/2026-10-03-agent-worker-postgresql-recovery.json)
passed with two real processes, natural lease expiry, one Tool call, one
evidence record and continuous product checkpoints. The private test used a
restricted database role but development authentication, loopback HTTP and a
controlled model; production HTTPS/mTLS, live-provider and real-device
acceptance remain open. The detailed runtime and workspace boundaries are in
`docs/agent-runtime.md` and `docs/operator-workspace.md`.

---

# 39. Typical Investigation Example

User:

```text
"Why is payment-api latency high?"
```

Workflow:

```text
Supervisor Agent
        ↓
Application telemetry
        ↓
Kubernetes health
        ↓
Node health
        ↓
VM / Hypervisor
        ↓
Network path
        ↓
Interface telemetry
        ↓
Recent config changes
        ↓
Historical comparison
        ↓
Root Cause Analysis
```

Output:

```text
Root Cause

Leaf03 Ethernet12 physical-layer degradation.

Evidence

CRC errors increased from 0 to 18,423.
Optical RX dropped to -18.2 dBm.
Packet loss began at 14:32:08.
Payment API P99 increased 34 seconds later.

Affected Resources

K8s-node17
K8s-node18
payment-api

Recommended Action

Move traffic to redundant link.

Confidence

94%
```

---

# 40. Development Phases

The detailed, status-bearing plan is maintained in
`docs/development-plan.md`. The sequence below captures product dependencies.
The Capability Studio is deliberately early: self-extension cannot be postponed
until after a conventional monitoring platform has already been built.

## Phase 0 — Runnable Vertical Slice

Current foundation:

```text
PostgreSQL-ready entity model
IP / MAC / wired attachment / Wi-Fi terminal history
alert rules, deduplication, acknowledgement, and resolution
collector-facing ingestion contracts
initial operations UI
versioned collector artifacts, deployments, workers, leases, and run history
bootstrap-authenticated worker enrollment and rotating worker credentials
credential-reference profiles and a fail-closed broker boundary
request-local bearer/basic/custom-header authentication for Prometheus and Loki
with Credential Profile adapter scope, protected-header rejection, and secret
redaction
revision-checked, audited observability backend edits and reversible disable
with stale-health invalidation
bounded JSON Schema validation and collector lifecycle audit events
Prometheus-compatible backend registry and bounded PromQL query boundary
versioned SNMP Exporter collector pack and non-container deployment templates
web device onboarding with protocol-neutral, credential-referenced connection intents
leased worker preflight, bounded evidence, retry, and readiness aggregation
versioned activation policies, immutable plan preview, approval, and deactivation
run-health promotion, failure/staleness degradation, and deployment-drift repair
provider/model routing and secret-reference configuration
persistent investigation, evidence, Tool Registry, and tool-call contracts
bounded LangGraph reason/tool/evidence kernel with structured model inference
```

This phase proves durable identity and alert state but is not yet the AI-native
product runtime.

---

## Phase 1 — Distributed Collection and Data Foundation

Build:

```text
generic CollectorDefinition and artifact schema
collector scheduler, leases, heartbeats, rate limits, and health
systemd/VM production packages; Compose remains development-only
Prometheus-compatible metrics plane and SNMP exporter pack
Windows metrics plus on-demand PSRP/CIM adapter
controller/API collector SDK
entity, relationship, observation, and event normalization
artifact registry foundations
```

Target:

> Multiple collector workers can safely collect hundreds to thousands of
> heterogeneous targets without protocol-specific logic entering the core model.

---

## Phase 2 — AI Operator Kernel

Build:

```text
AI provider, URL, model, secret-reference, and routing configuration
LangGraph durable investigation state
typed Tool Registry and execution policy
bounded planner/tool/evidence loop
read-only network, Windows, PromQL, log, and topology tools
checkpointing, streaming, budget limits, and L2 escalation
AI L1 home screen and situation workspace
```

Target:

> AI can autonomously perform a bounded, read-only investigation and expose every
> conclusion, tool call, evidence item, uncertainty, and escalation reason.

---

## Phase 3 — In-Product Capability Studio

Build:

```text
conversational Collector Designer
Tool and Skill Designer
workflow template editor for deterministic and agentic graphs
AI-generated topology and visualization definitions
schema/security validation
sandbox, fixtures, replay, and preview
versioned publish, canary rollout, health, export, and rollback
MCP gateway for external and user capability packs
local installed-capability readiness catalog
```

Target:

> A user creates a new API collector, topology view, diagnostic skill, or workflow
> inside iCheck without an IDE or a product release.

---

## Phase 4 — Situation and Incident Intelligence

Build:

```text
event correlation and Situation model
service impact and topology reasoning
incident lifecycle and root-cause analysis
historical and change timelines
dynamic views generated from investigation context
external ticket and collaboration integrations
```

Target:

> The primary UI is an AI-operated situation queue, while inventory and raw
> telemetry remain contextual evidence in dedicated subpages.

Implementation status on 2026-09-28: the first Situation slice is executable.
The platform persists Situations, Alert memberships, and ordered lifecycle
events; correlates distinct active Alerts by a versioned same-entity key;
preserves each Alert as inspectable evidence; and maintains acknowledgement,
attention reopening, priority, and all-members-resolved semantics. PostgreSQL
advisory transaction locking and a partial unique index protect the live
correlation key. Device/site-scoped APIs, the `/situations` priority queue,
canonical `/situations/{id}` focused evidence workspace, AI L1 priority rail,
dashboard counts, bounded legacy reconciliation, and durable
Situation-to-Investigation binding are implemented and tested. The focused
route loads one authorized Situation independently of the bounded queue and
keeps read-only detail navigation separate from explicit Investigation
creation. The
second slice derives minimized, evidence-addressable device/endpoint and
Knowledge Graph context with deterministic paths capped at three hops, exposes
it through a sixth read-only Agent Tool, and lets an authorized Situation focus
an immutable published topology specification. These paths are explicitly not
root-cause conclusions. The third slice separately persists evidence-linked AI
root-cause hypotheses with confidence history and human review, and enforces a
strict evidence- and authorized-node-bound service-impact assessment contract.
These records remain governed proposals and never overwrite deterministic
Situation truth. The fourth slice adds a scoped, revision-checked service
catalog with owner, criticality, impact class, SLO/RTO/RPO and audited component
bindings. Matching services enter the bounded impact graph through durable
catalog edges, and AI proposals snapshot the cited catalog revision. The fifth
slice adds reviewed, directional service dependencies with optimistic revision
checks, two-service scope enforcement, a dedicated GUI, one-hop Situation
expansion, durable dependency edge evidence, and immutable AI-assessment
dependency snapshots.
The sixth slice adds strict evidence-bound Investigation topology proposals,
authorization-scoped previews, a dedicated human review page, and atomic
publication through the existing immutable Artifact lifecycle.
The sixth-b slice applies the same separation to service-indicator
visualizations: cited Investigation evidence and frozen-scope selectors are
validated before proposal persistence, and only a reasoned human review may
atomically publish the ordinary immutable Artifact.
The seventh slice adds revisioned service/business indicator definitions,
idempotent observations, deterministic threshold and freshness evaluation,
bounded Situation evidence nodes, LangGraph Tool visibility, immutable impact-
assessment snapshots, and a dedicated Service Intelligence UI. The eighth
slice adds outbound ticket/collaboration adapters as exact published
`situation`-triggered Workflows with required governed MCP dependencies,
service run-as identity and scope, whitelisted typed-input mapping, an atomic
Situation-event outbox, unique Situation-linked Investigation dispatch, and
the existing approval/post-check/rollback boundary. This avoids hard-coding
ServiceNow, Jira, Slack, Teams, or private integrations into Situation logic.
The ninth slice adds deterministic `reviewed_service/v2` cross-entity grouping.
Only required components of one active reviewed service, observed within 15
minutes and resolving to one candidate Situation, may join. The membership
freezes service revision and component evidence at 0.85 confidence; ambiguous,
stale, oversized, and optional-component cases remain separate. Stable service
advisory locks protect simultaneous creation, and non-global callers must see
every member Alert or the entire Situation is hidden. This is grouping evidence,
not causal inference. The tenth slice activates revisioned Prometheus indicator
bindings through a standalone PostgreSQL-leased Worker. It reuses the guarded
Metric Backend boundary, enforces explicit finite scalar reduction and label
allowlisting, persists bounded retry/dead-letter health with hash-only errors,
and publishes deterministic idempotent service evidence. Configuration and run
health remain on the Service Intelligence subpage rather than the AI L1 home.
The eleventh slice adds first-class external incident references and signed
inbound status observation. Activation pins one producing MCP Tool, validates
remote ID/URL/status paths against its registered output schema, and terminal
commit accepts exactly one successful producer call. Ed25519 callbacks are
bounded by key ID, five-minute timestamp skew, 64 KiB payload size, strict
schema, and `(binding, provider event)` replay identity; only hashes and
normalized status facts persist. Stale remote timestamps are retained as
ignored evidence. Neither a remote reference nor a callback may change the
deterministic local Situation lifecycle.

The twelfth slice adds governed generic API/business-system indicator
publication without creating an unrestricted scheduler. A service indicator
binds one exact published Collector or schedule Workflow version. Collector
publication consumes the strict `icheck.service-indicator-observation/v1`
normalized envelope through the leased Knowledge Projection Worker; Workflow
publication maps one successful pinned read-only Tool result whose numeric,
date-time, and string-dimension paths were checked against its output schema.
Model prose is never metric input. Every observation retains the binding
revision, Artifact version, and Envelope or Investigation/ToolCall provenance;
Collector device/site scope must overlap a current service component, and
invalid, unbound, or cross-scope inputs fail atomically. Configuration and
recent provenance remain on `/services`, not the AI L1 home.

The thirteenth slice adds deterministic `qualified_topology/v3` symptom
grouping after exact-entity and reviewed-service policies. It accepts only
fresh active endpoint attachments, wireless sessions, or allowlisted
undirected LLDP/CDP/network-link Knowledge Relationships, with bounded row
search and exactly one active Situation candidate. Every membership freezes
the selected topology record, relationship type, timestamp, source and target,
target Alert, and policy limits at `0.70` confidence with
`causal_claim=false`. Stale, directed, unknown, inactive, oversized, and
ambiguous evidence fails closed into separate Situations. The impact graph
shows a distinct non-causal grouping edge; AI hypotheses never enter the
correlation transaction.

Live external MCP and webhook compatibility, vendor payload converters, and
multi-hop causal policy design remain Phase 4 work. Live lab evidence is still
required before claiming vendor compatibility.

---

## Phase 5 — Governed Action

Build:

```text
Ansible Runner and replaceable execution backends
change objects, pre-checks, post-checks, and rollback
RBAC and scoped credential broker
peer review and four-eyes approval
maintenance windows and risk policies
complete AI/tool/artifact audit trail
```

Target:

> AI can propose changes and execute approved actions without receiving
> infrastructure credentials or bypassing policy.

Implementation status on 2026-09-29: the first Phase 5 slices are executable for
Tools that publish `icheck.change-tool/v1`. An Agent action now creates a
durable, revisioned change plan that freezes targets, authorization scope,
action and dependency Tool/schema versions, risk, rollback, and a hash-only
idempotency reference. Exact same-Investigation pre-check and dry-run evidence
plus a bounded maintenance window are required before the existing four-eyes
interrupt accepts a dual-hash decision. The runtime automatically executes the
frozen read-only pre-check and dry-run, reuses their calls on LangGraph resume,
and runs the frozen post-check after action success. Stage argument mappings
may rename or nest frozen target values but cannot introduce other inputs.
Stage evidence may also expose a bounded peer-review preview, but only for
schema-proven booleans, numbers, or SHA-256 strings; raw configuration and
arbitrary string diffs remain outside the plan and model context.
For non-global Investigations, the contract must bind frozen target paths to an
iCheck Device ID or site. Creation and approval/execution resolve those objects
against the frozen authorization scope, preventing an external action adapter
from using a valid Tool permission against a cross-site target.
Approval and execution recheck drift and the active window. Successful
execution remains unverified until the exact post-check passes; failure or
failed verification exposes the frozen rollback request to the bounded Agent
loop. A requested rollback becomes a second proposal linked to the parent plan,
requires a fresh four-eyes decision, and binds its boolean result back after
execution. The original approval is never reused. Capability Studio and MCP
activation preserve this Tool contract, and
`/approvals` renders and manages the policy detail away from the AI L1 home.
Risk classes now resolve to four revisioned
`icheck.change-risk-policy/v1` records. They control execution admission,
maintenance-window requirement and maximum duration, bounded dry-run preview,
and authorization-target binding. Each plan freezes the policy ID, revision,
and effective values; policy drift blocks approval and execution. Policy edits
use optimistic revisions, require a reason, emit previous/current audit
snapshots, and live on the separate `/settings/change-policy` administrative
page.
Crash recovery reuses only exact terminal persisted action calls and never
replays an absent or still-running outcome. The first replaceable backend is a
separate Ansible Runner MCP service whose catalog pins the project, inventory,
runner, explicit individual targets, scalar parameters, stage playbooks, and
timeouts. It executes without a shell, limits events/results, accepts only
lease-bound credential headers, and keeps a durable apply-idempotency ledger.
Its rollback Tool has no recursive contract and is admitted only when it
exactly matches the parent plan plus a new peer approval. Code and hardened
systemd templates are present, but no live write pack is installed or
activated before lab acceptance. Legacy change Tools remain compatible with
the earlier approval kernel but are not production-ready until migrated to the
new contract.

---

## Phase 6 — Scale and Ecosystem

Build:

```text
collector and agent-worker horizontal scaling
multi-tenant isolation and regional control
artifact dependency and compatibility management
signed capability packs and organization catalogs
additional network, cloud, virtualization, storage, and application packs
capacity, reliability, security, and upgrade testing
```

Implementation status on 2026-09-29: signed multi-Artifact packs,
dependency/compatibility preview, transactional installation ledger, local
Catalog provenance, signed digest revocation with transactional runtime
quarantine, signed predecessor upgrades, compatible uninstall, signed remote
catalog discovery/acquisition, dual-signed catalog/pack/root key rotation,
purpose-scoped organization trust distribution, and external transparency
witness quorum/automated quorum-backed gossip are implemented. Signed exact-target
promotion receipts and durable automated witness/promotion delivery are also
implemented. Tenant/region isolation now spans request selection, regional
RBAC, ORM/write guards, transaction-restored PostgreSQL RLS, namespace-local
configuration, and every Worker process. As of 2026-10-02, publisher key/domain
and remote catalog natural identities are namespace-local too. The same signed
publisher document may be accepted independently without global key collisions;
purpose/expiry/domain containment and local advisory quarantine remain enforced.
On 2026-10-03, PostgreSQL 16.15 acceptance passed the namespace-local
identity/migration gate under non-owner authenticated HTTP and raw-SQL RLS,
including all duplicate-identity downgrade guards and refusal of an RLS-limited
migration role. Catalog refresh now refreshes its exclusive source lock and
holds shared current domain/key authority through publication, reverifying
exact bytes and validity after lock waits. Stale heads and committed containment
cannot be bypassed by cached state; unsupported transaction settings fail before
network fetch. The combined database suite passed 57 tests, including 24
publisher cases; focused catalog/trust regression passed 17 tests. Fixture
publisher transport does not accept live HTTPS, remaining trust mutation/recovery
races, production upgrade/backup datasets or live recovery ceremonies.

The subsequent distribution slice on 2026-10-03 adds 55 real PostgreSQL cases
and brings combined database acceptance to 112 tests. The full backend
regression passed 548 tests. Planned catalog/root rotations refresh locked
parent state and hold both authorities; exact-proof
retries create one durable outcome and cannot restore older state. Remote pack
admission rechecks catalog state after download and expiry/frozen distribution
after validation. Namespace-local lineage/digest locks coordinate uploads and
signed revocations without a cross-tenant bottleneck. Whole mutation transactions
bind explicit non-enforcing service callers too. Real backend-loss rollback and
controlled post-commit response-loss retry pass for the tested boundaries.
Publication, activation and execution still require their own governance.
That slice did not yet accept bundle/uninstall/publication/dependency races,
live transport, whole-server failover, production datasets or recovery ceremonies.

The subsequent bundle and installation lifecycle slice adds 42 PostgreSQL
cases, bringing combined database acceptance to 154 tests on PostgreSQL 16.15.
The final full backend regression passed 548 tests against this implementation.
Bundle reconciliation refreshes exclusive domain and managed-key state and
holds current-root authority; cached sequence, purpose/expiry, containment and
revocation cannot bypass admission. Late bundle/root/active-key expiry rolls
back reconciliation, head, receipt and audit together. Managed-signer installs
and bundle changes share the authority boundary without matching namespaces
sharing row locks. Install/upgrade and uninstall share lineage/digest locks;
cached Sessions cannot replay removed packs or overwrite original tombstones.
Concurrent retries and both uninstall/upgrade orders are accepted. Backend-loss
rollback and controlled response-loss reconciliation are tested. Bundle
sequence replay still fails closed and must be reconciled through history.
These mutations bind whole namespaces and reject unsupported PostgreSQL
transactions. Publication, new cross-pack dependencies, shared/reused Artifact
versions, other trust mutations and the live/production gates above remain open.
The integrated demo remains deferred.

The subsequent shared Artifact lifecycle slice adds 47 PostgreSQL cases,
bringing combined database acceptance to 201 tests on PostgreSQL 16.15.
The final full backend regression passed 548 tests against this implementation.
Creation/version allocation, validation/publication, pack admission, removal
and advisory quarantine share sorted namespace-local Artifact identity batches
before version locks. Exact external dependency reads share locks; embedded and
reused Artifacts take exclusive locks. Cached removed versions and revoked or
retired origins cannot bypass admission. Live exact dependency/reuse consumers
at installed pack heads block publication retirement, and both commit orders
are tested alongside namespace independence, concurrent version allocation and
caller-owned rollback/visibility. A higher compatible same-lineage release
revalidates identical retired content into a new validated candidate.
Single and manual batch publishers share lock order; dependency refresh and
whole-batch backend-loss/response-loss recovery are accepted. The frontend
type-check and production build passed without changing the system runtime.
That Artifact lifecycle slice left concurrent Studio ownership open; the
subsequent authoring acceptance follows. Other trust/source/policy/expiry races,
production datasets, live transport, scale and recovery remain separate gates.
These foundations enable no automatic action authority, and the integrated
demo remains deferred.

Studio authoring now shares one durable transaction contract across Collector,
Workflow, Topology, Visualization, Report, Tool and Skill. UUID request keys bind
authenticated intent; database-clock leases fence old owners across model audit
commits without holding locks over transport. Saved model bytes and known usage
precede compilation, and allocation commits with the exact Studio candidate.
Validation, message, audit and immutable outcome commit together. Saved-byte
recovery never creates another model call; a missing response stays uncertain
even if its completed-call audit can reconcile known usage. New keys explicitly
create new iterations, while failed drafts and sealed generation history remain
inspectable. Publication requires the exact reviewed version ID and commits
Artifact and Studio state together. Historical retry snapshots are not current
heads or publication authority. Broader publisher authority/time races, live
model/vendor, production recovery and scale gates remain separate, and the
integrated demo remains deferred.

This authoring slice adds 156 native cases, bringing the final combined
PostgreSQL 16.15 run to 357 tests. The final full backend regression passes 549
tests, and frontend type-check/build pass with an isolated compatible toolchain.
Non-owner subjects cover concurrent ownership, saved-byte and known-usage
reconciliation, compiler drift, sealed history, actual candidate-commit backend
termination, lost responses, reviewed-version publication and populated
multi-namespace migration. The sole Alembic head is `l4n6p8r0t2v5`; this does not
apply a production migration or deploy the product.

Promotion source, signer/domain and policy authority now extend across the
admission/publication transaction. Readers retain shared policy/source locks;
sequence and configuration writers take the matching exclusive boundary,
including absent rows. Pack lineage/digest precede sorted domains/keys and the
complete Artifact/version batch. Publication verifies the signed receipt
snapshot and current stage/lifetime/manual/four-eyes policy again. A final
pre-commit check rejects late signer/attestation expiry and rolls back heads,
sequence, outcome, audit and transparency together. Exact completed retries
remain historical evidence with original provenance, not renewed authority.

Promotion policy, source and receipt natural identities are tenant/region local.
Policy lookup uses the namespace instead of the old literal singleton ID.
Migration `m5o7q9s1u3w6` preserves legacy IDs and every signed/history row, enforces
one policy per namespace, requires all-namespace visibility and refuses an
unsafe downgrade. Live transport, physical crash/failover, other publisher
mutations and M7 execution authority remain separate gates. See
`docs/capability-promotions.md` for the transaction and retry contract.

This promotion slice adds 99 native cases, bringing the final PostgreSQL 16.15
run to 456 tests. The final backend regression passes 552 tests, and frontend
type-check/build pass. Generated acceptance databases/roles were removed and
the private socket-only server stopped. That slice's sole Alembic head was
`m5o7q9s1u3w6`; no production migration, deployment or integrated demo was run.

Planned environment-promotion key handover is now implemented at
`/studio/catalog/promotions`. The short-lived dual-signed statement binds
organization, exact source/target stages and environments, both fingerprints,
and the latest accepted sequence/head. Both signers retain purpose and managed
organization/domain authority. Unexpired accepted but unpublished receipts
must drain first; a changed accepted head requires a new signed statement.
Exclusive source authority serializes handover with admission and containment.
Final time/context checks and the pin, sealed proof/history, original
authenticated operator/reason, audit and transparency commit together.

No private key enters iCheck, and handover does not reset the sequence, revoke
a key or publish/activate anything. An exact historical retry returns its
original record even after a later handover; it never repins current authority
or overwrites an advanced head. Migration `n6p8r0t2v4x7` preserves existing
sources and refuses removal of recorded handover history. Live independent
source-checkpoint witnesses, lost/revoked environment-key recovery and live
multi-environment acceptance remain separate work. These controls do not grant
autonomous action authority or complete M6/M7.

This handover slice adds 40 native cases. The final combined PostgreSQL 16.15
suite passes 496 tests and the backend suite passes 576, with only the existing
non-failing TestClient warning. Frontend type-check/build and isolated mocked
browser download/upload/rejection/retry/history flows pass. Desktop and
390-pixel screenshots verify readable layout after the header correction.
Generated databases/roles were removed, and the private PostgreSQL, browser and
frontend fixtures were stopped. The sole migration head is `n6p8r0t2v4x7`; no
production migration, deployment or integrated demo was run.

Required independent source-checkpoint witness policy is now implemented in
the same promotion Studio subpage. The target reviews its local witness
allowlist, quorum and evidence age, and separately pins each source's log ID
and epoch. Zero quorum explicitly means not required and preserves old signed
envelopes byte-for-byte by omitting the optional evidence field. Enabling or
tightening policy is reviewed configuration, not permission to publish or act.

The existing signed gossip document binds the exact checkpoint in the signed
promotion statement. All supplied proofs require current local witness pins,
purpose-scoped keys/domain authority, canonical digest/signature validity and
bounded clock, expiry and age. Duplicate identities/fingerprints, promotion or
pack self-witnessing and insufficient allowlisted quorum fail closed. A new
wrapper cannot refresh an old checkpoint. Unsigned region labels do not prove
source organization/environment; distinct cryptographic pins do not prove
independent hosting or operators.

Admission/publication retain policy/source authority, existing configuration
rows, sorted witness rows and one combined sorted signer/domain batch through
commit. Final checks reject late expiry. Receipt and sealed evidence digest,
verified signer metadata, original policy and authenticated operator commit
together. Publication rechecks current policy and the saved signer binding.
Changed source pins require draining unexpired unpublished receipts and do not
reset sequence. Accepted receipts cannot be amended; completed historical
retries grant no new authority. No network or model call occurs under locks.

Migration `o7q9s1u3w5y8` adds namespace-local controls and append-only witness
decisions, preserves old signed history, and refuses data-bearing or
RLS-hidden downgrades. Focused tests passed 26 ordinary and 33 native cases,
including both actual commit orders, direct existing-row writers, final expiry,
backend/response loss, namespace isolation and sealed evidence. The full
backend suite passed 602 tests. Isolated mocked browser policy retry, binding,
evidence attachment and quorum display pass; desktop and 390-pixel layouts were
inspected without horizontal overflow. Live witness/source-log, recovery,
other publisher paths and M7 action authority remain separate acceptance.
The final complete PostgreSQL 16.15 suite passed 529 tests, with the existing
single non-failing TestClient warning. Generated databases/runtime roles were
confirmed removed and the private socket-only server stopped; browser/frontend
fixtures were also closed. The sole migration head is `o7q9s1u3w5y8`.
No production migration, deployment or integrated demo was run.

Pre-authorized emergency environment-promotion key recovery is now implemented
at `/studio/catalog/promotions/recovery`, separate from planned handover and
organization-root recovery. The enabled current authority must first sign an
exact source/target policy, binding independent local trustee/witness pins,
quorums of at least two, a 1–72-hour delay and evidence-age limits. Sealed
historical authorization remains cryptographically verifiable after the old
key is lost or revoked; current successor/trustee/witness authority is still
required. Planned handover or superseding authorization retires old policy.

The incident source must be contained. Successor and trustee signatures bind
the policy, exact context, preserved accepted head and independently witnessed
current local incident checkpoint. Proposal preview is read-only and grants no
execution authority. After proposal, a different authenticated operator waits
the mandatory delay and submits fresh witnessed proposal coverage. Pin change,
sealed execution/retirement decisions, audit and transparency commit atomically
with final current-authority/time checks. The source stays disabled. Explicit
restoration requires another witnessed current local checkpoint covering
execution; the ordinary enable API enforces the same gate.

Emergency recovery does not require publishing potentially compromised pending
qualification. Existing accepted head and receipt history remain unchanged;
historical retries return original evidence while current-pin publication
checks refuse the old receipt. Later-pin retries cannot repin old authority.
Cancellation preserves all signed evidence. Distinct fingerprint quorums are
not proof of independent hosting/operators or tamper-proof whole-database
administration. There is no network/model call under authority locks.

Migration `p8r0t2v4x6z9` adds sealed policy, ceremony and append-only event tables
with tenant/region isolation, exclusive terminal decisions, immutable-row
guards and data-bearing/RLS-hidden downgrade refusal. The recovery file
workflow exports public templates for external signing; the existing root
HSM/KMS gateway is not automatically a signer for these new purpose-separated
formats. See [the recovery contract](./docs/promotion-emergency-recovery.md).

At that slice, the full regression passed 623 backend and 561 PostgreSQL 16.15 tests,
including 20 new real-signature ordinary API cases, one synthetic-metadata
SQLite migration case and 32 native authority/process-loss/isolation/migration
cases. Type-check/build pass with isolated Node 22.23.3; mocked browser flows
and inspected desktop/390-pixel layout pass without horizontal overflow.
Generated databases/roles were removed and private PostgreSQL/browser/frontend
fixtures stopped. The sole migration head then was `p8r0t2v4x6z9`; no production
migration, deployment or integrated demo was run. Environment-specific signing
integration, live independent ceremonies, remaining publisher paths, scale and
M7 action authority remain open; this does not complete M6/M7.

The organization-root emergency re-anchor now has a retained-authority
transaction boundary as well. Domain-first locking aligns proposal,
execution, cancellation and containment; proposal/execution retain policy,
selected successor/trustee keys, witness pins and checkpoint offer, then
revalidate live quorum, current authority and expiry at commit. Pin change,
policy retirement, terminal evidence, audit and transparency are atomic, and
late failure rolls them all back. A read-only local checkpoint lookup no longer
initializes or commits state during a ceremony. Migration `q1s3u5w7y9a2`
seals the signed/context fields and proposed deadline in recorded root policy
and ceremony rows, permits only one-way complete retirement/terminal updates,
and refuses data-bearing or RLS-hidden downgrade. Focused native acceptance
passes 18 signed PostgreSQL cases across both authority/containment commit
orders, late expiry, unsafe transaction modes, ordinary-runtime SQL history
guards and downgrade safety. These guards do not prove external witness
independence or defend against a database owner; other publisher trust
mutation paths and live recovery still require acceptance. The complete
regression passed 623 backend and 579 PostgreSQL 16.15 cases with the existing
single non-failing warning in each. Generated databases/runtime roles were
removed and the private socket-only server stopped. The sole migration head
is `q1s3u5w7y9a2`; no integrated demo or production migration was performed.

Pre-incident organization-root recovery policy admission now retains the
latest recorded policy, any active policy and the selected local
root/trustee keys under a domain-first `READ COMMITTED` transaction. The
signed envelope is verified after those locks; final key, domain and expiry
checks precede the atomic
policy/supersession/audit/transparency commit. An exact retry after a lost
response returns the sealed historical outcome, even after domain
containment, while changed proof or reason is refused. Policy versions
advance from retained history, allowing the new root to authorize version
two after a planned dual-signed rotation retires version one. Fourteen
focused native cases pass with real signatures, non-owner sessions, both
authority commit orders, late failure rollback and concurrent retries. This
is not a live independent recovery drill or acceptance of the other publisher
lifecycle paths; the integrated demo remains deferred.

At that slice, the complete regression passed 623 backend and 593 PostgreSQL
16.15 cases, each with the existing single non-failing warning. Generated
databases/runtime roles were removed and the private socket-only server
stopped. The sole migration head remains `q1s3u5w7y9a2`; no production
migration or deployment was run.

Root-domain restoration after emergency re-anchor now retains the exact
post-execution log head, witness quorum, selected signed attestations,
witness pins and both root/witness key authority until commit. It refuses
enablement when the head advances or quorum expires during lock acquisition;
late failure rolls back the enablement, audit and transparency event. The
witness-policy writer takes its row lock before mutation so both commit
orders are enforceable. Migration `r2t4v6x8z0b3` seals recorded checkpoint
offers and attestations against runtime SQL update/delete and refuses
data-bearing or RLS-hidden downgrade. Eighteen focused native cases pass
with actual signatures, non-owner RLS, lock waits, late expiry, head drift,
lost-response retry and durable-proof guards. This remains distinct from
live independent witness operations, database-owner tamper resistance and
the other publisher paths; the integrated demo remains deferred.

The complete regression passes 623 backend and 611 PostgreSQL 16.15 cases,
each with the existing single non-failing warning. Generated databases and
runtime roles were removed; the private socket-only server was stopped.
The sole migration head is `r2t4v6x8z0b3`; no production migration or
deployment was run.

Trust-domain bootstrap now holds its local root key under a shared PostgreSQL
lock until commit and rechecks key usability after flushing the domain and
its evidence. Planned dual-signed root rotation now rechecks both locked
keys, the signed statement expiry and the domain head at the final commit
boundary. Thirteen native cases cover both revocation/acceptance lock orders,
late expiry and unsafe transaction modes. At that slice, a domain-creation
response loss still required a namespace-local identity lookup. These controls
narrow the M6 publisher lifecycle gap but do not replace live offline-root
signing, independent recovery drills
or the pending integrated demo.

The final regression passed 623 backend and 624 PostgreSQL 16.15 tests,
each with the existing single non-failing warning. Generated test databases
and roles were removed, the private socket-only server was stopped, and the
sole migration head remains `r2t4v6x8z0b3`. No production deployment or
integrated demo was run.

Domain creation now optionally binds a client retry key to a namespace-local,
append-only receipt containing the effective actor, canonical request digest
and created domain ID. Exact retries return the domain's current state after
a response loss, including if the original root was later revoked or rotated;
changed requests conflict, and legacy callers without a key retain the
identity-lookup requirement. The Studio form retains an unchanged attempt's
key across a retry. Migration `u3w5y7a9c1e4` adds RLS and runtime immutability
to the receipt, with a populated or RLS-hidden downgrade guard. This closes
the bootstrap response-loss gap for keyed callers, not live offline-root
signing, database-owner tamper resistance or the integrated demo.

The final regression passed 623 backend and 637 PostgreSQL 16.15 tests,
each with the existing single non-failing TestClient warning. Studio
type-check, lint and the isolated Node 22.23.3 production build passed.
Generated acceptance databases and roles were removed and the private server
was stopped. The sole migration head is `u3w5y7a9c1e4`; no production
migration, deployment or integrated demo was run.

The M1 scale harness now pins the sole migration head resolved from this
checkout rather than an obsolete revision. On 2026-10-03, a fresh private
PostgreSQL 16.15 database at `u3w5y7a9c1e4` and a non-owner RLS role passed
all eleven functional gates for 1,000 synthetic targets, two Collector
Workers and two Projection Workers. The
[saved report](./acceptance/scale/reports/2026-10-03-private-postgresql.json)
records 1,000 successful cycles/endpoints, both lease reassignments, no Worker
errors or dead letters, 38.64 target cycles/second and 13.43-second projection
p95 lag. The database and role were removed afterward. This is PostgreSQL
code-path evidence on a development host, not production sizing, real exporter
cardinality, live-device acceptance or an operating-system crash/restart drill.
The M1 exit and integrated demo gates remain open.

On 2026-10-03, a separate
[Projection Worker process-loss probe](./acceptance/scale/reports/2026-10-03-projection-worker-postgresql-recovery.json)
passed nine gates in a fresh private PostgreSQL database under a non-owner,
non-RLS-bypass role. The first actual Worker was SIGKILLed while blocked on a
locked endpoint row. A second actual Worker reclaimed the naturally expired
15-second lease and completed the same projection on attempt two, leaving one
endpoint and one IP observation. This establishes bounded Projection Worker
crash recovery, not live-device readiness or production capacity.

A separate
[Collector Worker process-loss probe](./acceptance/scale/reports/2026-10-03-collector-worker-postgresql-recovery.json)
passed thirteen gates on a fresh private PostgreSQL database. The first actual
Collector process was SIGKILLed during a controlled HTTP request; after its
15-second lease naturally expired, a second process claimed and completed the
same Deployment. The original token could neither ingest nor complete its
cancelled Run. The replacement produced one Envelope, one completed projection,
one endpoint, and one IP observation. These controlled process probes do not
establish production mTLS, real-device, infrastructure-restart, or capacity
acceptance.

Regional Collector/Agent scaling
policies and an advisory-locked recommendation controller are implemented, but
an immutable, idempotent application-event boundary now accepts authenticated
provider receipts. A separate opt-in systemd actuator now reconciles only
root-allowlisted Collector/Agent instances, verifies fresh matching Worker
health, and drains active leases before process scale-in. Verified external
HSM/KMS recovery signing and health-gated automatic rollout rings are also
implemented. Dual-credential mTLS identity for distributed Collector and
remote Agent HTTP routes is implemented with trusted-proxy binding, staged
rotation, cancellation, and revocation. Collector clients use the authenticated
HTTPS lifecycle routes. The Agent Worker now uses the versioned
`icheck.agent-runtime/v1` HTTPS protocol for lifecycle, graph checkpoints,
reasoning, Tool execution, progress, and nested MCP/approval interrupts and has
no direct database credentials. Durable workflow dispatch is isolated in a
regional control-plane worker. Private PostgreSQL process-kill/restart
functional acceptance now passes; production Worker CA/proxy rollout and
HTTPS/mTLS fault drills remain work.
The LangGraph saver tables are owner-provisioned and forced tenant/region RLS
is verified before non-owner runtime traffic. An owner-only orphan inventory
reports unresolved thread counts and hashed samples without committing DDL or
deleting rows; governed retention, quarantine, purge and production-scale
backfill acceptance remain open. An eight-way native graph test also verifies
concurrent tenant/region checkpoint isolation; production load and proxy
acceptance remain open. A synthetic local 10,000-Investigation checkpoint
backfill passed across ten regions, but production-equivalent upgrade and
lock-contention acceptance remain open. Owner checkpoint migration and audit
now bound each lock wait; a local contention test verifies failed attempts
leave namespace/RLS changes uncommitted and permit a retry. The saver's
autocommit migrations remain a separate phase. Existing invalid, wrong-column,
or name-colliding saver indexes are now rejected before owner DDL; production
repair remains DBA-controlled. Prebound enterprise
OIDC Authorization Code/PKCE browser federation is implemented with one-time
encrypted transactions and local RBAC ownership. Source/secret-bound
trusted-proxy browser federation is also implemented with prebinding and a
hash-only attempt ledger. CI workload federation is implemented as an exact
issuer/audience/subject-bound OIDC/JWT exchange with one-time jti consumption,
short-lived icw_ tokens, and live identity checks on every API request. Live
IdP/identity-gateway/CI-provider acceptance and governed group/role mapping
remain open. Cloud/hypervisor host actuation, live vendor recovery drills, and
production scale programs remain open.
The dedicated `/settings/identity` Web UI and its reasoned Principal-disable
and role-revocation lifecycle are implemented; raw federation subjects and
session/token hashes never return to that page.
Exchange endpoint mTLS/rotation and manual atomic promotion publication are
implemented.

---

## Phase 7 — Governed Autonomous Operations

Only after evidence quality, rollback, and governance are mature:

```text
automatic remediation for pre-approved low-risk operations
automatic incident verification
automatic rollback
closed-loop operations
```

Example:

```text
Alert
 ↓
AI diagnoses
 ↓
known low-risk remediation
 ↓
policy permits automation
 ↓
execute
 ↓
verify
 ↓
close incident
```

High-risk changes should continue to require human approval.

Implementation status on 2026-10-02: the execution-health foundation is now
implemented. Exact published Collector, Tool, Skill and Workflow versions have
namespace-local revisioned policies, bounded immutable assessments, integrity
hashes and observation expiry. A regional advisory-locked quality controller
records assessments and deduplicated degradation/recovery evidence. Studio has
a separate quality configuration/history page; the read-only Agent Tool exposes
minimized current assessment citations. Governed MCP calls pin Artifact and
activation identity before execution and reject upgrade drift; legacy calls
are not retroactively attributed to today's registry.

These assessments explicitly carry no automation authority. Execution success
is not functional correctness, remediation verification or authorization.
Execution from reviewed low-risk preapproval, automatic rollback and incident
closure remain unimplemented and disabled. Earning those transitions still requires exact
capability/target/condition policy, mature independent outcome evidence and live
safety/recovery acceptance; no global autonomy switch substitutes for them.
See `docs/capability-execution-quality.md` for the current contract and gates.

The separate remediation-outcome quality basis is also implemented for
published governed change Tools. Phase-bound calls enforce a fresh post-check
after the actual action; persisted schemas, hashes, targets, peer decisions and
causal sequencing are revalidated. Replayed idempotent purposes do not inflate
success samples, and rollback restoration is not success of the original purpose.
Published Tool contracts may additionally require a bounded, typed pre-state to
desired post-state transition. A boolean post-check cannot mask a value mismatch;
legacy Tools retain an explicitly declared-boolean basis. This is evidence from
the Tool's read-only observations, not independent proof of vendor truth.
For new governed evidence, a structured transition mismatch now fails the
post-check at binding time and leaves the plan `rollback_required`, even when
the Tool's boolean success flag is true. The existing separate approval for
rollback remains mandatory.

Studio and the scoped read-only Agent Tool label this evidence explicitly.
See `docs/remediation-outcome-quality.md`. This does not grant unattended authority
or accept the semantic accuracy of live vendor/device post-checks.

A separate reviewed preapproval record now binds one published low-risk Tool
version, active device, Alert condition and exact argument template. An
independent persistent Principal reviews it; a plan eligibility preview checks
the current governed evidence, Alert and immutable per-Alert budget claims.
Alert freshness and completed precheck/dry-run freshness are independently
bounded; a current Alert cannot revive old prerequisite calls.
New policies also require a published state-observation contract. Preview
checks that the read-only pre-state differs from the fixed desired action value
and is within the Tool contract's stricter causal age bound; an old Tool version
without that contract cannot be promoted by changing policy fields.
The Web authoring picker searches and pages only currently ready Catalog Tool
versions with that low-risk, device-bound observation contract. Selection is
not authority: a changed MCP endpoint policy, server health or credential
binding blocks the plan preview even if the operator already selected the Tool.
Reviewer role removal invalidates eligibility. A claim primitive exists but is
not connected to action execution. It shares a policy read lock across
different Alerts while serializing claims on each Alert; an exact retry can
retrieve its immutable debit after Alert freshness expires, but cannot regain
eligibility or execution authority. The internal ledger passed real PostgreSQL
row-lock contention, non-owner tenant/region RLS and bounded failure/retry
acceptance on 2026-10-03. Claims require `READ COMMITTED` with DBAPI autocommit
disabled; other configurations fail closed rather than losing atomic locks
or retaining a stale ledger snapshot after a lock
wait. The complete empty-schema migration chain also passed upgrade,
downgrade and re-upgrade on PostgreSQL 16.15. These results do not accept the
future execution gate, whole-server crash/failover, production upgrade data,
or long-duration capacity. The preview never approves or executes an action.
New plans freeze a bounded Situation/Alert identity set in their hash;
later Alert membership and repurposed Alert rows cannot establish preapproval
causality. As of 5 October, the separate execution bridge below integrates the
budget and execution-time gates; live semantic validation remains required
before enabling unattended operations. See
`docs/reviewed-change-preapprovals.md`.

Implementation update on 2026-10-05: the primary-action authority bridge is
implemented, not enabled on this host. An independent persisted reviewer can
qualify one exact reviewed policy revision with current, zero-failure structured
outcome evidence for its fixed device and action template, an expiry, explicit
independent-validation confirmation and acceptance reference. This reference
records the reviewer's assertion; it does not fetch external reports or prove
vendor/device truth. Quality assessments and previews remain non-authorizing.

With the default-off host gate explicitly enabled and mandatory governed Tool
contracts enforced, the LangGraph action path can use that qualified policy
after fresh precheck/dry-run. Exact plan approval, per-Alert debit, immutable
authorization receipt, audit and queue transition commit atomically. Current
reviewer permissions/device scope, reviewed material, pinned quality policy,
fresh exact-template outcomes, frozen Alert origin, source freshness, target,
arguments, prerequisites and remaining budget are checked again immediately
before execution-start. The switch does not waive any of those checks or stop
network I/O already admitted. No ambiguous action result is automatically
replayed. Unqualified, expired, saturated or out-of-scope candidates retain the
existing human interrupt. High-risk and rollback actions cannot inherit this
primary-action grant.

The dedicated policy subpage now exposes independent qualification and recorded
grant history, including the host gate state. Native non-owner PostgreSQL tests
cover immutable RLS-bound authority history, concurrent budget/retry behavior
and backend loss before commit. Controlled Agent and browser fixtures cover the
policy path and GUI, not real devices or production transport. Separate bounded
automatic rollback, verified incident closure, representative live semantics,
whole-server recovery and sustained capacity remain open. M7 and the full
product are not complete; the integrated demo stays deferred.

---

# 41. MVP Recommendation

Do not try to build every category initially.

The first AI-native MVP must prove three product loops:

```text
Observe:
  a generated or built-in collector produces normalized evidence

Investigate:
  a durable, bounded agent loop uses tools and explains its conclusion

Extend:
  a user creates, tests, publishes, and revises one capability inside iCheck
```

Keep the infrastructure scope focused on:

```text
Network
Linux
Windows
```

Technology:

```text
FastAPI
PostgreSQL
Prometheus
SNMP Exporter
generic HTTP collector
Netmiko
Nornir
PowerShell/CIM
LangGraph
Artifact Registry and sandbox
React
```

Initial AI capabilities:

```text
find_device()

get_interface_status()

get_interface_metrics()

get_bgp_neighbors()

get_route()

get_mac_entry()

get_arp_entry()

ping()

traceroute()

get_windows_cpu()

get_windows_disk()

query_windows_event()

query_metrics()

query_logs()
```

Initially keep all tools read-only.

---

# 42. Architectural Rules

## Rule 1

AI must never receive infrastructure passwords.

## Rule 2

AI should call typed tools, not arbitrary SSH commands.

## Rule 3

Structured APIs are preferred over CLI.

## Rule 4

Every state-changing action creates a Change Request.

## Rule 5

Every Change Request requires peer review according to policy.

## Rule 6

Requester cannot approve their own change.

## Rule 7

All actions are audited.

## Rule 8

Every AI conclusion should expose evidence.

## Rule 9

CMDB represents infrastructure knowledge; TSDB stores time-series telemetry.

## Rule 10

Dynamic infrastructure state should retain history.

## Rule 11

Execution technology must remain replaceable behind the Tool Platform.

## Rule 12

Monitoring templates and tools may be AI-generated, but must be deterministically validated.

## Rule 13

The AI Agent Runtime is the product kernel; monitoring screens and chat are
projections of its state, not separate products connected by an AI add-on.

## Rule 14

Collectors are protocol-neutral, versioned artifacts. SNMP, APIs, WMI/CIM,
streaming, and future protocols use the same lifecycle and normalized contracts.
Before a generated Collector can run, the operator must bind it to a current
registered Device identity or explicitly identify an external API source and
record a reason. The Worker rechecks that ownership against current inventory
before each assignment. This preserves arbitrary API collectors without letting
an unknown generated target silently bypass the Device correction lifecycle;
generated direct-device targets must name the selected Device IP or inventory
name. An unrelated API remains an external source. DNS aliases, proxies and
custom target fields still require a separate, enforceable attestation design
before this can be called complete endpoint identity proof.

## Rule 15

Collectors, topology views, tools, skills, workflows, and visualizations must be
creatable and iterable through conversation inside iCheck.

## Rule 16

Generated capabilities never silently modify the production runtime. They pass
typed validation, sandbox tests, policy checks, versioned publishing, scoped
rollout, health observation, and rollback.

## Rule 17

AI providers, models, execution engines, collectors, and tool transports must be
replaceable behind iCheck-owned contracts. MCP is supported at integration
boundaries but is not mandatory for every internal tool.

## Rule 18

Docker Compose is for development and demonstration. Production components must
support independent VM/bare-metal deployment and horizontal scaling; containers
remain optional.

---

# 43. Product Definition

iCheck should ultimately be described as:

> **An AI-native, self-extensible IT operations agent platform that continuously
> discovers, observes, understands, diagnoses, and manages heterogeneous
> infrastructure, while allowing users to create and evolve its collectors,
> topology, skills, tools, and workflows through conversation.**

A shorter product description:

> **iCheck is an extensible AI infrastructure engineer with observability,
> capability creation, automation, and governance built in.**

---

# 44. Final Technology Position

### Monitoring

```text
Prometheus ecosystem
SNMP Exporter
OpenTelemetry
VictoriaMetrics
```

### Infrastructure knowledge

```text
PostgreSQL
```

### AI

```text
LangGraph orchestration
provider-neutral model adapters
typed tools and MCP gateways
```

### Network diagnostics

```text
Native API
gNMI
NETCONF
Nornir
Netmiko
```

### Infrastructure management

```text
Ansible
Ansible Runner
```

### Windows

```text
PowerShell
CIM/WMI
PSRP / WinRM
windows_exporter
```

### Governance

```text
Change Request
Peer Review
Four-Eyes Approval
RBAC
Audit
Rollback
```

### Core principle

```text
AI decides WHAT it needs.

The Capability Platform decides HOW to do it.

Humans decide WHETHER risky changes are allowed.
```

---

# 45. Long-Term Goal

The long-term vision is a closed-loop AI operations system:

```text
                 Infrastructure

                       ↓

            Continuous Observability

                       ↓

               Infrastructure Model

                       ↓

                 AI Reasoning

                       ↓

             Incident Understanding

                       ↓

             Recommended Remediation

                       ↓

                 Policy Engine

                       ↓

                  Peer Review
             (when risk requires)

                       ↓

                 Automation

                       ↓

                  Validation

                       ↓

                  Learning
```

Learning includes two distinct loops:

```text
Operational loop:
observe → investigate → act → verify

Capability loop:
identify missing capability → generate artifact → test → publish
→ observe runtime quality → revise or roll back through conversation
```

iCheck must learn by producing explicit, reviewable, versioned artifacts. It
must not rely on invisible prompt drift or uncontrolled self-modification.

The system should evolve from:

```text
Monitoring
```

to:

```text
Understanding
```

to:

```text
Assisted Operations
```

and finally:

```text
Governed Autonomous Operations
```

without sacrificing auditability, explainability, or human control.

## Implementation update — rollback restoration, 5 October 2026

Change contracts can now declare a separate read-only `rollback_check` and
typed `rollback_expectations` covering every original pre-change semantic
observation. The Agent runs it after the separately peer-approved rollback.
Frozen target/schema/Tool pins, plan-and-phase identity, original-state freshness
and bounded post-rollback timing gate restoration. `awaiting_rollback_check`
does not mean restored; false or mismatched observations cannot become success.
Legacy boolean-only rollback remains explicitly weaker. Raw original and
restored state is not copied into quality manifests.

Historical primary-action receipts now bind the immutable approved revision,
while current evidence revisions are verified separately. Post-action evidence
and later policy revocation do not invalidate a genuine completed-action record.
The approvals UI distinguishes these hashes and exposes restoration evidence.
Migration `t8v0x2z4b6d9` preserves old contracts and refuses downgrade across
new restoration configuration/history or through an RLS-limited connection.

This is a prerequisite for governed automatic rollback, not its authorization.
The next authority slice must separately qualify restoration outcomes, bind a
rollback to one exact failed parent action and frozen rollback template, lock
that parent for at-most-one admission, commit a distinct immutable receipt and
budget decision, and revalidate scope/expiry/revocation before execution-start.
Original remediation quality must remain failed even after successful recovery.
Uncertain write outcomes cannot replay; current read-only proof and explicit
reconciliation are required. Verified incident closure remains separate work.

The reviewed-execution host gate remains off. Production transport, identity,
Worker/action recovery, representative upgrades/load, live model/device packs
and GUI lab acceptance remain open. No integrated demo is authorized by these
isolated fixtures; see the release-readiness audit and lab acceptance gates.

## Implementation update — independent recovery and request-level continuity, 5 October 2026

The separate one-shot rollback authority is now implemented: independent
human-reviewed restoration baselines qualify the exact frozen recovery
template/target; primary success plus a fresh semantic post-check failure
permits at most one parent-serialized admission. Manual and automatic recovery
share that slot. Atomic immutable receipts, append-only revocation and
execution-time checks preserve history without another primary debit or budget
refund. Restoration never makes the original purpose successful or closes its
Alert/Situation. Both reviewed-execution host switches remain off.

Delegated MCP results bind to the original Worker, execution attempt and Tool
call. Uncertain writes cannot be redispatched even by a replacement Worker;
committed terminal results recover without another adapter command. Controlled
real Worker SIGKILL/lease takeover tests distinguish an adapter-changed target
whose result was never recorded from a committed restoration recovered after
revocation. They are not live-vendor or whole-server failure acceptance.

The Agent loop also supports independently reviewed sequential requests in one
reasoning iteration through per-request checkpointed Tasks. Completed requests
do not shift a later approval's interrupt position or lose their citations.
Internal/MCP success records a bounded, immutable exact-call citation receipt
with terminal completion and audit. Legacy unbound internal results are not
backfilled from guesses; current result/source drift rejects recovery. Typed
rejection accounting retains actual read-only prerequisites and earlier
completed actions without fabricating the rejected action's result. Migration
`v0x2z4b6d8f1` preserves those namespace-isolated receipt records and refuses a
lossy downgrade. Rollout requires drained investigations and coordinated
API/Worker versions, not hot replacement of an active checkpoint layout.

The runtime and acceptance documents record the controlled code boundaries.
Verified causal incident closure remains unfinished. Production identity/TLS,
vendor semantic packs, representative upgrades and sustained load, GUI lab
enrolment/investigation and real recovery remain separate release gates. M7 and
the complete product goal remain in progress; the integrated demo is deferred.

## Implementation update — truthful Situation resolution, 5 October 2026

Manual acknowledgement/resolution now serializes on a freshly loaded Situation
and rechecks current authenticated object scope after the lock wait. Resolution
requires complete available membership and current resolved Alert rows, never
a cached zero count or snapshot. Unpersisted source edits are not discarded or
flushed after the check. The manual operation recomputes its supporting
summary/counters and records one event/audit atomically. Correlation refreshes
other cached Alerts and reopens a resolved projection when sources are active;
a new occurrence after closure retains the generation boundary.

These are supported lifecycle guarantees, not independent proof of the original
AI purpose or database enforcement against every raw write. Both manual and
all-Alert-state projection events declare that they are not independently
verified and supply no AI closure authority. Existing outcome-quality and
rollback semantics are unchanged; restoration cannot make a failed original
purpose successful. Native lock/RLS tests and regression collection boundaries
are recorded separately; no autonomous closure switch is enabled.

## M7 incident-closure contract — next implementation, not yet delivered

Verified closure must be a separate explicit capability and permission, with a
default-off host gate plus a current independently reviewed exact policy. It
must not be a side effect of Agent text, healthy quality scores, delivery
callbacks, manual resolution or successful restoration.

The next implementation must:

1. Freeze a bounded complete causal membership/identity set for the exact
   primary purpose, target and namespace. The existing plan-origin snapshot
   contains only then-open Alerts and is not by itself a complete closure
   contract. Legacy/partial origins cannot be promoted by guessing or editing
   today's mutable registry.
2. Reuse causal outcome verification for the exact committed primary action
   and passed structured post-check. Reject failed/rolled-back purposes,
   unknown writes and pending relevant actions. No Tool result boolean or
   mutable `verified` status can substitute for those records.
3. Require fresh, independently qualified read-only quiet-state observations
   bound to the actual Alert conditions and exact sources after the action.
   A resolved Alert flag, changed desired configuration, stale Collector
   snapshot or a Tool observing its own claimed success is insufficient.
   Vendor truth and independence require live acceptance in addition to code
   identity/schema/freshness checks.
4. Revalidate current policy/reviewer/ownership/revocation, target scope,
   source identity/content and complete membership at the commit boundary.
   Establish one consistent order with Alert/correlation writers; source
   upsert/resolve/deduplication and observation-order races must be accepted
   before the authority is exposed. Do not serialize the entire fleet behind
   a namespace-wide mutex or perform external I/O under database locks.
5. Commit a namespace-isolated immutable closure receipt and audit atomically
   with the state transition. Exact historical retry may read that receipt,
   never reauthorize a new closure. Reopened/new-generation events preserve
   the old receipt without claiming that its proof is current permission.
   Migrations must reject lossy/limited-visibility downgrade; legacy manual
   history remains explicitly unverified rather than backfilled as proof.
6. Present separate Alert-state, pending verification, independently verified,
   rejected/stale and reopened states on the focused Situation page. AI may
   propose or execute only through the typed governed API; no homepage dump,
   hidden auto-close branch or unrestricted generated Skill bypass is allowed.

Acceptance must cover real non-owner RLS, competing close/source writers,
source and membership drift, revoked ownership, exactly-once audit/receipt,
commit-loss recovery, legacy denial and focused authenticated GUI flows. Live
lab semantic/adapter/identity/transport and sustained capacity gates remain
required before enabling authority or running the integrated demo. M7 and the
full-product goal remain in progress.

## Durable Alert-condition ordering — 5 October 2026

The Alert-source prerequisite above is now implemented; it does not implement
independent incident-closure authority. A tenant/region/source-key cursor
serializes supported positive, quiet and unknown observations, including the
first observation before any Alert exists. It retains the source identity and
high-water timestamp across manual resolution and subsequent Alert generations.
The database also enforces at most one active Alert for each namespace/key.
Only that key and its current incident parent are serialized, not the fleet.

Newer observations may advance the condition. Older observations cannot change
an Alert, count, recovery state or workflow outbox. An exact same-time verdict
is idempotent; conflicting same-time verdicts record conflict without choosing
quiet and require a newer sample. Missing/invalid RSSI records unknown rather
than recovery and prevents an older recovery sample from winning. Evaluated
Alert timestamps more than five minutes in the future are rejected, not allowed
to poison the cursor. This is not a general inventory clock/order guarantee.
Boolean RSSI is rejected before API integer coercion; it cannot become a
zero-strength measurement and quiet an existing alarm. Invalid snapshots do
not mutate the saved telemetry. The cursor orders explicitly delivered
observations. At that source slice, full/partial snapshot absence and generic
generated-collector recovery declarations still needed explicit source
contracts, not inference from session deactivation or an unrelated event.
The controller-local snapshot follow-up below implements the first contract;
generic independently qualified verdict/provenance remains open.

Source identity cannot be rebound. The retained original rule ID survives
deleting its mutable Rule row. HTTP Alert results expose their observation
disposition; a stale observation with no historical Alert is refused explicitly,
never represented by a fabricated episode. A future network event causing
Alert evaluation rolls back its inventory transaction and returns an input
error. Existing MCP OAuth challenges receive episode-specific keys; legacy
challenge resolution stays an unverified administrative action.

Alert acknowledgement/manual resolution lock and refresh the source before the
Alert and recheck current object scope after waiting. They do not assert quiet
source truth. Correlation locks only the selected Situation in joined candidate
queries, avoiding reverse locks on another producer's Alert/member rows.
Source ordering and row isolation are not causal verification or permission.

Migration `w1y3a5c7e9g2` follows `v0x2z4b6d8f1`. Stop API ingress and every
Alert-producing API/Collector/Projection/Agent/quality/transport path, drain
source-producing leases/runs, migrate with all-namespace visibility, then update
and restart the matching code. The migration verifies durable Collector,
Projection and Agent drains under table locks, but cannot attest that old API
processes were stopped or prevent arbitrary old binaries from later bypassing
the new service. Mixed-version/hot cutover is not accepted.

Backfill preserves all Alert history and labels it `legacy_unknown`, never
inferred quiet proof. Conflicting historical identities are quarantined without
guessing a source; duplicate active legacy keys refuse upgrade and require
explicit reconciliation. RLS, immutable source identity, monotonic time/revision,
same-time conflict rules, cross-source reference checks and watermark deletion
denial protect the cursor. SQLite uses canonical UTC microsecond text, not
rounded Julian-day comparisons. A populated cursor or RLS-limited role refuses
lossy downgrade. No legacy record is deleted to make a migration pass.

Quality evaluation follows the same ordering: insufficient/stale evidence
advances an unknown source cursor instead of allowing older health to clear a
degradation. Older assessment/audit history is retained without replacing the
policy's current assessment or next evaluation. Equal-time assessments keep
the more conservative verdict and source conflict; future-dated assessments
are not current health. This does not confer independent action/closure proof.

The exact test runs, collection boundaries and remaining gates are recorded in
`acceptance/alert-condition-ordering-2026-10-05.json`. Independent fresh causal
quiet-state proof, exact-policy/reviewer/ownership/revocation checks, immutable
atomic closure authority/receipt, commit-loss recovery and a focused proof UI
remain the next implementation. The two write-authority gates stay off; live
vendor/identity/transport, sustained capacity and all other M1–M7 gates remain
open. No integrated demo or production migration is authorized by these checks.

### Next closure implementation boundaries — proposed, not delivered

Use a separate closure-policy/observer qualification, verification candidate,
and immutable receipt. Their permission, host gate and exact independently
reviewed policy must be distinct from primary-action or rollback authority.
The existing Tool catalogue and sealed evidence bindings are reusable plumbing,
not proof that a newly generated observer is independent or truthful.

At new primary-plan creation, capture a versioned complete bounded closure
origin, including acknowledged/resolved supporting members, exact Alert
episodes, source cursors, Rule/condition content and target identity, not only
the current open-Alert origin. Oversized, hidden, partial, ambiguous and legacy
origins are ineligible; do not backfill completeness. A new source generation
cannot reuse the old purpose's closure authority.

Qualify exact read-only observer versions and their actual transport/credential
and source bindings. A different Tool name or `read_only` flag is insufficient.
Reviewed typed predicates must test the original Alert condition, not merely
the configuration value modified by the action. Missing values, untrusted or
cached measurement times, unknown/conflicted sources and an unqualified adapter
remain pending/rejected. Representative vendor freshness and independence still
require live acceptance; receipt structure cannot manufacture semantic truth.

Run observations outside the closure transaction through existing bounded,
fenced Worker/Tool contracts. Preserve exact action/postcheck and observer
receipts; failed/rolled-back purposes, uncertain writes or relevant pending
actions deny closure. Candidates carry source and complete-membership pins and
expire. There is no I/O inside the final authority transaction.

The final commit must be source-writer compatible. Multi-key inventory/rule
batches do not currently establish one universal key order, so a closer must
not hold some cursor locks while waiting indefinitely for others or for the
parent. The initial design uses bounded existing-cursor/Alert/parent NOWAIT
admission in a rollback-only-on-contention operation: busy means retry/re-probe,
never a global fleet mutex or guessed success. Revalidate full scope, ownership,
reviewer/qualification revocation, source identity/content/time and membership
after admission. Any newer contrary/unknown source, changed episode or new
member invalidates the candidate. Accept actual competing batch/source/closure
and revocation transactions before exposing the capability.

Keep an explicit incident lifecycle generation. Reopening preserves old receipts
and advances that generation; it does not overwrite proof or reauthorize a new
closure. State, generation-bound receipt, event and audit commit together, with
immutable/namespace guards and lossy-downgrade refusal. A lost commit response
recovers the exact historical receipt; retries cannot spend new authority.

Present this on a focused Situation verification surface and a separate policy
configuration page. Distinguish Alert-state resolution, pending proof,
independently verified, stale/rejected and reopened history. The AI workspace
links to those surfaces instead of accumulating endpoint/proof tables at home.
AI-generated Skills and Workflows use the same typed governed API with no
alternate closure path. Source support gaps must stay visible, not simulated.

## Coherent controller snapshots and explicit absence — 5 October 2026

The supported direct and generated wireless snapshot paths now share one
namespace/controller-local durable collection watermark. A coherent snapshot
uses one UTC clock: omitted client times inherit it, explicit times must match,
connection times cannot be later, normalized MACs cannot repeat and completeness
is a strict boolean. Keep vendor last-traffic/association metadata separate from
fresh observation time. Reject a clock more than five minutes ahead even when
the body has no clients. Bound normalized bodies to eight MiB/10,000 clients.

The last normalized body is compared directly, not through a new SHA256
verification job. Client order and MAC/timezone spelling do not create a
different retry. Older snapshots cannot create/update/close sessions, addresses,
metadata or Alerts; empty first snapshots also retain this ordering boundary.
Same-time conflicting bodies retain the previously applied inventory and
conflicted/unknown controller-owned signal conditions. No same-time retry clears
conflict. A strictly newer coherent batch is required. API and projection
results expose accepted/stale/duplicate/conflict/legacy_unknown explicitly.

Complete-snapshot absence closes missing sessions and deactivates that
controller's current Wi-Fi IP associations while preserving all history and
other collectors/controllers. It advances exact retained controller-owned RSSI
conditions to unknown, including already inactive clients and disabled/deleted
Rules, rather than recovering their open/acknowledged alarms. Partial-snapshot
omission changes neither session membership nor condition truth. A similarly
named manual/independent source key is not owned merely because its suffix
matches a controller. Neither collection completeness nor disappearance is
independent causal quiet-state evidence.

Generic network input cannot bypass this contract with source wifi_controller.
Generated wireless DTOs reject boolean RSSI before integer coercion; invalid
envelopes keep the existing redacted dead-letter history without telemetry writes.
Controller kind/enabled state and authenticated object scope are refreshed after
waiting; generated projections also recheck the current deployment site before
committing. Relevant pending controller, watermark or Endpoint edits are refused
before their values can be flushed/overwritten. Concurrent controller writers
create one namespaced MAC entity atomically, lock endpoint rows in deterministic
MAC order and preserve monotonic shared endpoint metadata clocks. This does not
claim universal Alert batch ordering or general ARP/DHCP/IP/attachment freshness.

Migration x2z4b6d8f0h3 follows w1y3a5c7e9g2. Stop old ingress and source
processes, drain durable Collector/Projection/Agent work, migrate with
all-namespace visibility, then restart matching code. The migration refuses
legacy cross-namespace controller references. Backfill preserves sessions and
uses legacy_unknown with an empty, uninvented body. Equal/older legacy samples
do not reapply inventory. RLS, exact controller reference, immutable identity,
revision, full-precision time and deletion guards protect history; recorded or
hidden watermarks refuse lossy downgrade. It is not a hot mixed-version gate.

The typed origin-bound contract described next implements the logical
generated-collector measurement/definition/credential/target pins. Independent
collector/transport/physical qualification remains open; generic inventory evidence ordering and
efficient retained-condition indexing/load acceptance also remain distinct.
Streamed absence reads bound memory, not controller poll latency or fleet
capacity. Continue with those prerequisites and the separately proposed
independent closure authority/receipts/proof UI above. Production transport,
vendor/semantic qualification, six-class GUI lab and all M1–M7 gates remain
open. No write gate, production migration or integrated demo is enabled here.

## Origin-bound generated conditions — 5 October 2026

Keep condition evaluation in the platform, not in an Agent- or Worker-supplied
verdict. A published Collector version declares bounded typed predicates and
freshness. Its admitted, authenticated run emits measurements through the
protocol-neutral `icheck.collector.condition/v1` contract. Missing, invalid-
quality, type-incompatible and expired measurements are unknown. A boolean or
numeric-looking string is never converted into a numeric recovery.

Capture seals normalized measurement plus exact published material, assignment,
current deployment/entity ownership, Worker issuance/mTLS identity and actual
credential-profile grant/revision. Labels supplied by producers are descriptive
only. Projection refreshes current origin after deployment/run/Worker/entity
locks and refuses changed origin or accepted bytes. These are logical registered
identity pins, not vendor freshness or physical-device attestation.

Durable source generations separate deployment/version/assignment/profile-
revision/condition/entity. A new definition or credential generation cannot
quiet an older generation's Alert. Individual Worker origins remain in sealed
admissions; matching replacement Workers can share the logical source.
Older observations cannot mutate current truth; exact same-time measurements
are duplicates and unequal same-time measurements conflict even when both
predicates agree. Newer measurements are required after conflict. Receipt and
Alert mutation commit together; exact recovery/concurrent retries do not replay
the mutation. Generic Alert input cannot impersonate reserved source keys.

Capability Studio exposes these definitions in structured authoring, validates
generated observation fixtures and runs the existing hardened sandbox before
reviewed publication. Bounded literal mappings let the user name a condition
when the source API has no such field; literals compile as data, not source
instructions. Old specifications without conditions retain their serialized
shape. Candidate canary evidence remains separate from production admission.

Migration `y3a5c7e9g1i4` adds append-only namespace-protected admissions,
source generations and interpretation receipts with reference/authority guards.
There is no forged legacy provenance backfill. Stop old ingress/producers,
drain Collector/Projection/Agent work, migrate with all-namespace visibility
and restart matching code; populated or hidden provenance refuses downgrade.

Every result is explicitly not independently verified and does not authorize
incident closure. The next gates are generic inventory evidence ordering,
retention/indexing/load and independently qualified causal quiet evidence;
then reviewed immutable closure authority, revocation/recovery and focused
proof UI. Full M1–M7 production and six-class Web GUI lab acceptance remain
open. This slice enables neither host write gate nor the integrated demo.

## Source-local network address and attachment observations — 5 October 2026

The direct and normalized generated paths share durable namespace/Endpoint/
source/Collector/dimension clocks for ARP, MAC-table, DHCP and manual inventory.
Metadata, IPv4, IPv6 and attachment progress independently. Explicit address
sets support aliases/dual stack and replace both families only for their source;
legacy singular IP replaces one family. Missing fields observe nothing rather
than erase previously known data. Explicit empty sets and detach advance even
an empty-first boundary, preventing delayed resurrection. Port omission keeps
known attachment history; the inherited model still has one port/VLAN attachment
per source/Collector/MAC, not complete multi-port cardinality.

Compare bounded canonical JSON directly. Older samples do not mutate; exact
same-clock retries are duplicates and contradictions retain applied inventory
with conflict state until a strictly newer dimension. Conflicting items within
one batch are refused atomically. Source isolation, deterministic device/Endpoint
locks, post-wait current authorization/assignment checks and bounded indexed
history reads protect supported writers. They do not qualify physical identity,
vendor clocks/completeness, arbitrary SQL or sustained fleet throughput.

The Endpoint API and dedicated subpage expose retained source quality. Ordinary
accepted observations are explicitly logical, not independently verified or
incident-closure authority. A legacy unknown-port observer association is not
physical attachment proof. Keep those distinctions out of inferred AI verdicts.

Migration z4b6d8f0h2j5 follows y3a5c7e9g1i4, retaining active/inactive history as
legacy_unknown without inventing bodies. Stop old producers/ingress, drain
durable work/leases, migrate with all-namespace visibility and restart matching
code. RLS/reference/identity/revision/time/deletion/downgrade guards are isolated
verified; no production migration or hot mixed-version acceptance is made.

Next: close Studio's registered versioned-record and structured-mapping gap,
then remaining cardinality, native historical backfill, independent physical/
causal qualification and reviewed closure authority/recovery/proof UI. The
network record (private development evidence; not distributed) separates
125 affected ordinary/174 native checks from live/rendered/full-suite acceptance.
Full production and six-class GUI lab gates remain open; demo is deferred.

## In-product normalized output authoring — 5 October 2026

Studio's output vocabulary is now the runtime's eight registered versioned
projection contracts, with platform-selected envelope kind and actual DTO/
domain sample validation. The authorized catalog is available to the designer
and in a collapsed Studio reference. Custom dotted names remain raw-only;
structural registration and sandbox success are not independent live proof.

Structured mappings support whole arrays/objects, indexed source paths and
bounded copy-on-write nested destinations, not arbitrary expressions or code.
Overlapping parent/child destinations fail. Source collection-clock mapping
is optional but, once selected, missing/null/invalid timestamps fail without
manufacturing freshness. Reviewed version defaults pin output and record/
identity/clock paths; deployment overrides cannot silently change them. Corrections
are new reviewed versions, and existing published material needs separate
drained revalidation/rollout. Failed candidates retain terminal usage/specification
history but no publishable normalized output.

Controlled publication-to-Device-admission-to-real-sandbox-to-scoped-projection
checks cover IP aliases, Wi-Fi clients and graph entities/relationships on
PostgreSQL RLS. Native populated historical backfill is also checked. These are
isolated code prerequisites, not a browser, physical identity, vendor clock or
production cutover ceremony. Broader declarative array-element transformations,
multi-port/VLAN cardinality, independent causal closure authority/recovery/proof
UI and the full production/GUI lab program remain work. Demo remains deferred.

## User-authored vendor-array normalization — 5 October 2026 follow-up

The preceding array-element gate now has a bounded implementation: the Studio
designer can propose scalar extraction, per-item objects and nested arrays with
relative paths. Primitive records/items use the trusted `value` wrapper. No
vendor-specific IDE change, filtering, dropped rows, coercion or executable
expression is required or permitted. Preserve observed order, duplicates,
nulls and empty lists; reject missing/malformed input instead of manufacturing
terminal absence. Registered output contracts retain their typed/domain checks.
Singleton wrapping is explicit, and representative fixtures must show each
sourced item path.

Plans and entire-response traversal have fixed safety ceilings; reviewed
Artifact metadata records them and deployment inputs cannot expand them.
Existing sandbox AST/network/resource controls remain unchanged. Controlled
Linux-style address and controller-client flows reach normalized inventory
through actual publication, target admission, hardened transform and non-owner
PostgreSQL projection. Structural success is still not vendor truth, independent
causal evidence, production capacity or incident-closure authority.

The Studio subpage retains collapsed technical guidance rather than adding it
to the AI operator home. Browser acceptance found and corrected clipped mobile
panels and overflowing navigation; a compact keyboard-operable workspace menu
and stacked narrow-screen layout are checked with isolated fixtures. Terminal
source-quality labels remain on the Endpoints subpage. Full production identity,
vendor GUI authoring, multi-port/VLAN cardinality, causal closure/recovery/proof
UI and six-class live-lab acceptance remain unfinished. The frozen full ordinary
repeat for that array/quota boundary passed 1,217 cases with 24 skips; it does not
cover later v2 work. No integrated demo has started. See the
current bounded verification record (private development evidence; not distributed).

## Explicit multi-port/VLAN sets and retained logical history — 5 October 2026

The subsequent non-wireless cardinality prerequisite is implemented through
`icheck.inventory.network-observation/v2`, without rewriting v1 or Wi-Fi
snapshot semantics. An address/VLAN or interface/VLAN pair is an independent
binding; a single MAC can have multiple simultaneous pairs. Source/Collector
ownership and explicit IPv4/IPv6/dual-stack scope bound replacement. Omitted or
null sets preserve earlier observations and clocks, explicit empty sets clear
only declared dimensions, and a clear-before-first-observation prevents delayed
resurrection. Reappearance creates a new episode, retaining inactive history.
Only exact known normalized bodies can be cross-version duplicate retries;
unknown legacy ports do not become empty sets or qualified history.

Users can author vendor address/port object-array mappings in Studio and follow
existing reviewed publication, Device admission, hardened transformation and
scoped projection. The catalog now contains nine contracts. No arbitrary model
code, filtering, coercion, sandbox expansion or deployment-clock override is
introduced. Existing guarded tables/cursors support the cardinality, so head
stays `z4b6d8f0h2j5`; a mixed-version source-owner rollout still needs review and
coordination.

Focused endpoint badges distinguish VLANs, bounded Agent evidence discloses
history truncation, and main/Studio topology renders distinct stable parallel
paths. Preview counts disclose the 16-node/32-edge display cap. Final affected
checks pass 218 ordinary and 233 actual non-owner PostgreSQL cases; 24 frontend
unit tests and final typing/lint/build plus desktop/mobile fixture checks pass.
The complete ordinary repeat at this v2 boundary passes 1,287 with 24 skips,
not full native or lab acceptance. Physical/source completeness,
independent causal quiet and reviewed incident-closure authority/recovery/proof
UI, broader authoring UX/accessibility, production identity/transport/rollout/
load/restart and live vendor/six-class GUI lab gates remain unfinished. Logical
sets are not causal proof, and no integrated demo or live collection has started.
See the [contract](docs/collector-contracts.md#explicit-ipvlan-and-portvlan-binding-sets-v2)
and verification record (private development evidence; not distributed).

## Collector source acceptance and incident closure boundary

External semantic, identity and observation-clock validation now has a separate
append-only proposal, independent human acceptance and revocation ledger.
Qualification pins full exact source/version/assignment/Device/entity/credential/
Worker material and the current mTLS policy; it is reusable across later polling
receipts until drift, expiry, role/scope loss or revocation. The evidence
environment is explicit. Controlled fixtures and lab attestations do not become
production acceptance, and no software check proves the honesty of an external
validation reference.

The source-qualification subpage is reached through actual Situation Alert
provenance and keeps governance details out of the L1 homepage. Its read-only
quiet check covers one current Alert episode, requires a fresh accepted typed
quiet receipt after an accepted active measurement and rechecks current origin
and peers. It grants no incident closure permission, exhaustive Situation
coverage, automatic physical verification or causal attribution to a repair.
Original logical receipt flags remain false. Newer repeated quiet polls retain
the known episode pointer instead of creating a null-provenance receipt.

Affected verification passes 122 ordinary and 157 migrated non-owner PostgreSQL
checks; typing, strict full lint and production build pass. The additive migration
head is `a5c7e9g1i3k6`, not a production deployment claim. The complete ordinary
core repeat passes 1,332 with 24 skips before the final implementation-material
permission guard; final affected checks verify that narrow delta separately.
Generic Alert readers cannot inspect raw Collector snapshots. Authors/peers
need current `capabilities.read`, rechecked after waits; withdrawal does not
depend on that material-read permission. Exact reviewed Situation closure ownership/revocation/
loss recovery/proof UI and Agent Tool wiring, broad browser/accessibility and
deep-history capacity, production identity/transport/secrets/coordinated rollout/
load/restart, live model/vendor semantics and the six-class GUI lab remain
unfinished. Both action authority gates remain off and the demo remains deferred.
See [the source contract](docs/collector-source-qualification.md) and
verification record (private development evidence; not distributed).

## Reusable Situation recovery criteria and closure prerequisites

The 6 October 2026 recovery component binds exact independently accepted sources
to reusable reviewed sampling criteria. A fresh exhaustive check covers every
correlated Alert, including historical episodes, and validates both active and
quiet provenance against the accepted Worker/source origin. Environment,
expiry, current peers/scope, sample count/duration/gap/freshness and membership
are checked again; changed, clipped or unsupported evidence fails closed. One
template can cover multiple incidents without repeated per-incident human
acceptance. Old active episodes cannot inherit new Worker acceptance merely
because the source ID matches.

The transaction locks all selected deployments before entering origin chains,
uses fail-fast lower locks to avoid waiting with earlier chains held, and locks
Situation last. Fresh membership/state/scope and wall-clock checks follow the
parent wait. Immutable policy/review/revocation ledgers have forced namespace
RLS and direct SQL guards. The new head is `b6d8f0h2j4l7`; original logical
receipts and clocks keep their meaning. No production migration was performed.

A dedicated Situation subpage supports human policy authoring, independent
acceptance, withdrawal and expiring read-only proof. It exposes no incident
close button. Final affected checks pass 159 ordinary, one SQLite migration
smoke and 207 migrated non-owner PostgreSQL cases; typing, strict lint, build
and controlled desktop/mobile flows pass. Temporary services and generated
database/role objects are cleaned up. These results are not a current full
product, live vendor or production-capacity acceptance.

Executable closure is a separate authority. The subsequent component below
implements admission/finalization, ownership/attempt epochs, atomic receipts,
retry recovery, related-action fences and Agent Tools. Explicit generation
replacement and current versus historical closure GUI remain code gates.
Verified remediation must additionally bind typed action/pre/post
evidence; source recovery alone does not attribute causality to a repair.
Production identity/transport/secrets, coordinated rollout/load/restart,
broader authoring/accessibility and live model/six-class GUI lab gates remain
open. Both action host switches remain off and the integrated demo is deferred.
See the [recovery contract](docs/situation-recovery-policies.md) and
verification record (private development evidence; not distributed).

## Reviewed closure ownership and Agent runtime

The 6 October backend component now implements independently qualified,
revocable closure authority; exact membership-bound intent; one lease owner
with monotonic attempt epochs; and atomic closure/event/audit/receipt commits.
Finalization consumes fresh whole-Situation recovery and structured related
action proof inside the fenced transaction. Lost commit responses recover
historical receipts rather than replaying closure or erasing a committed result
after authority withdrawal. Earlier automatic resolved-state events and source
receipts retain their non-authorizing meaning.

`source_recovery` and `verified_remediation` are separate bases. The latter pins
the complete published semantic Tool material and an exact Situation-bound
independently approved desired-state transition. Structured rollback restoration
is not remediation success. Uncertain/in-flight/boolean-only/identity-free
actions block closure; the quiet window follows terminal action verification.
Both bases retain false repair-causality and automatic physical-truth flags.

Native PostgreSQL uses shared transaction fences for normal writers and an
exclusive fence for closure proof, with source locks before fail-fast action
locks, the Situation parent and final ownership recheck. Database guards retain
RLS, immutable history, exact lineage and monotonic ownership. Migration
`c7e9g1i3k5m8` does not deploy or enable the feature on this host.

Agent Tools enforce caller snapshots and current roles/scope, require exact
Situation binding for mutation, and keep request identity/lease secrets inside
the runtime. A dedicated control-plane path avoids a self-blocking physical
action proposal and recovers a committed closure before completing a lost Tool
journal. Fresh read-only recovery checks use distinct observation keys; expired
or changed retained proof cannot be advertised as fresh.

Final affected verification passes **201 ordinary** and **266 migrated non-owner
PostgreSQL** tests. The selected suites include SQLite migration roundtrip,
actual controlled LangGraph execution, real bearer authorization, native writer
fences and parent waits, immutable history, current role/scope/expiry denial and
receipt recovery. They do not establish current whole-product regression,
new-Tool Worker process-loss, browser or live acceptance. The private database
and generated roles were cleaned up. See the
verification record (private development evidence; not distributed).

The subsequent immutable action-target catalog replaces the namespace scan
with indexed lookup and a related/unknown-action proof budget. Closure GUI,
grant discovery, explicit generation replacement and deep history/reconciliation
remain code gates. Sustained fleet capacity is still unaccepted.
Production identity/transport/secrets/coordinated
rollout/load/restart, actual new-Tool Worker loss recovery, full accessibility,
live model/vendor semantics and the six-class GUI lab also remain open. All
three reviewed-execution host switches remain off; the integrated demo and full
goal are not complete. See [the closure contract](docs/reviewed-situation-closure.md).

## Immutable action routing and fleet closure lookup

The 6 October routing component retains exact admission-time Situation/Tool/
Plan/rollback binding and complete frozen target material in append-only scoped
ledgers. Device/site keys and explicit unknown routing have composite indexes.
Closure unions these with exact Situation-bound actions; unrelated known history
does not consume the 256 related/unknown-action proof budget. Unknown or clipped
history cannot be silently trusted, discarded or made complete by a success label.
Routing provenance does not grant execution permission or replace semantic proof.

Native Plan insert and deferred proposal fallback retain every committed action;
closure makes fallback immediate before lookup, including flushed actions in its
own transaction. Native guards derive complete keys and prohibit historical
retargeting. Rollback without a separate Plan uses the original frozen Plan,
not mutable rollback arguments. Migration `d8f0h2j4l6n9` backfills only frozen
material and refuses undrained work/claims or namespace-limited visibility.
Populated history cannot be downgraded away.

Final affected checks pass **222 ordinary**, **288 native broad** and a **24-case
native routing repeat**; two late-added drain cases give 290 distinct native
cases across runs, not a single final full-suite result. Symbolic 1,000-record
unrelated-history checks and actual sparse EXPLAIN index plans pass, but sustained
fleet load/latency, production rollout/restart and physical vendor truth remain
unaccepted. Temporary databases/roles and private PostgreSQL are cleaned up.

Focused closure GUI and scoped grant discovery are implemented in the subsequent
component. Reviewed generation replacement, deep-history/unknown-routing
reconciliation and actual new-Tool Worker loss
recovery remain code/acceptance gates. Whole-product repeats, accessibility,
production identity/mTLS/secrets and live model/six-class GUI lab remain open.
All three execution gates stay off; the full goal and integrated demo remain
incomplete. See the [routing contract](docs/action-target-admissions.md) and
verification record (private development evidence; not distributed).

## Focused reviewed closure workspace

The 6 October workspace separates independent closure governance from the AI
home and recovery evidence. It adds scoped bounded policy/grant discovery with
exact older-record lookup, independent authority review/revocation, explicit
manual admission/finalization/release and historical owned-request recovery.
Every source binding must be visible to both current and initiating authority,
including sources outside current Situation membership. Accepted records and
historical membership comparisons are candidates/history, not fresh permission.

Receipt lists project metadata and counts instead of loading full proofs. Exact
owner GET reads one retained receipt without acquiring a lease, finalizing or
replaying closure. Stable pinned intents and transient-memory-only tokens handle
response loss; namespace/identity changes, denied reads and operation-generation
fences erase old context and ignore delayed responses. The page cannot enable
execution. New review requires material access; independent withdrawal and exact
release/read recovery retain their separate authority checks.

Selected ordinary regression passes 180 and the final workspace repeat 24;
native broad passes 313 and final workspace 24, with 314 distinct native cases
across runs rather than a single full-suite result. Typing, strict lint, 31
frontend tests, production build and 39 controlled browser assertions pass.
Desktop and 390px layouts were inspected. No migration was added; the isolated
database/roles, private PostgreSQL, browser sessions and preview were cleaned up.
These checks do not accept live API authentication or physical vendor semantics.

Remaining implementation/acceptance: reviewed source-generation replacement;
deep history and unknown-routing reconciliation; actual new-Tool Worker crash/
transport recovery; whole-product regressions and broad authoring/accessibility;
production identity/CA/mTLS/secrets/coordinated rollout/load/restart; live models
and vendor/controller semantics; six-class GUI lab. All three host gates remain
off. The full product and integrated demo are not complete. See the
[closure contract](docs/reviewed-situation-closure.md) and
workspace verification record (private development evidence; not distributed).

## Historical closure proof authorization

Historical closure and original Agent journal/checkpoint/detail history now
require both current and initiating read access to every retained member,
reviewed policy source and frozen typed action target. Today's membership,
mutable arguments and handler/history projection changes cannot redirect that
boundary. Unknown action routing needs global read scope. A fresh closure
cannot admit an unreadable complete proof; metadata discovery remains separate
and non-authorizing.

Authorized historical recovery still works after execution/grant/peer withdrawal
or expiry. It returns unchanged evidence without fresh qualification, a new
lease/token, physical action replay or a new digest. Generic Investigation
list/page results filter inaccessible original closure contexts and reject
their cursors; unrelated histories retain their existing permissions.

The retained-reader regression passes 225 ordinary cases, and final Agent/API
verification passes 131 with all 47 new scope cases covered. Native broad
passes 346 before the later Agent-history guard; the final native repeat passes
131, with 362 distinct affected native cases across those runs. These are
component boundaries, not current full-native or live-model/vendor acceptance.
A complete ordinary backend repeat passes 1,514 with 24 skips and eight warnings
in 1,994.33 seconds at the pre-replacement code boundary.
The private PostgreSQL fixture was stopped/removed after database/role counts
were 0|0. No frontend code changed; all host gates remain off and no demo ran.

Next is explicit independently reviewed source-generation replacement. Old
measurements and identities must remain historical; new origins need their own
acceptance, with no fabricated quiet samples or inherited retired authority.
Deep history/unknown reconciliation, actual new-Tool Worker recovery,
whole-product and broader authoring/accessibility/privacy, sustained load and
production identity/transport/secrets/rollout/restart, live vendor/model and
six-class GUI lab acceptance remain open. See the
[closure contract](docs/reviewed-situation-closure.md) and
verification record (private development evidence; not distributed).

## Reviewed source generation replacement contract

The component has a full [implementation contract](docs/reviewed-source-generation-replacement.md).
Internal proposal/review/revocation and scoped historical-read governance now
exist with additive immutable native ledgers. Internal atomic retirement and
producer fencing now exist, together with separate default-off recovery v2;
public replacement execution and compatible closure integration remain
unimplemented. The contract covers active old
episodes and a quiet new generation with no Alert, as well as resolved history.
Independent equivalence approval, permanent retirement and fresh new-source
sampling are separate. Supersession archives the old episode without rewriting
its measured status/clocks or fabricating quiet samples, while current counts,
Situation projections and Agent open-alert queries change consistently.

Old policies do not inherit a new generation. New recovery criteria explicitly
reference accepted historical mappings and count only new-generation samples.
Repeated updates preserve original retirement and require fresh bounded mapping
authority; unknown/stale/conflicting targets and producer/cutover races must fail
closed. Runtime-owned exact retries, complete retained read scope, focused GUI,
native RLS/reference guards and coordinated default-off deployment remain part
of implementation and acceptance. The preceding full ordinary regression
finished at an unchanged code boundary with 1,514 passing cases; the integrated
demo remains gated on the unfinished implementation and release acceptance.

The governance service distinguishes retained old qualification from current
new qualification, accepts quiet-only new sources without creating Alerts,
rejects changed normalized predicates/entities, requires independent human
acceptance and checks current plus initiating scope. Acceptance alone performs
no cutover, recovery or closure. Internal retirement, producer race fencing,
current projection updates and explicit repeated-generation revalidation now
preserve old measured truth. Explicit recovery-policy mappings and compatible
proofs, plus API/GUI/runtime-owned Agent execution, must follow before the feature can ship.

The governance boundary passes 167 affected ordinary and 158 migrated non-owner
PostgreSQL cases; this does not accept full replacement execution, API/GUI/Agent
integration or a production migration. The isolated server/database/role
fixtures were cleaned up. See the
governance verification record (private development evidence; not distributed).

### Internal permanent source cutover — 6 October 2026

The internal executor records an immutable retirement and exact old/new cutover
receipts under separate default-off execution authority. It archives only the
old active episode through a guarded link, preserves all measured clocks/status
and condition state, and updates affected Situation projections/events/audit
atomically. Resolved historical episodes retain their measured resolution; a
quiet new generation needs no fake Alert. Target freshness must cover both old
projected and already-sealed pending observations. Delayed old observations
remain retired history and cannot reactivate current monitoring.

Retired generations are permanent; later historical revalidation explicitly
references original retirement instead of silently chaining expired authority.
Current monitoring excludes superseded episodes while historical reads scope
both sources, both cutover receipts and every retained Alert pointer. Native
RLS/reference/link and deferred projection checks are in additive migration
`f0h2j4l6n8p1`. The final affected repeat passes 281 ordinary and 397 migrated
non-owner PostgreSQL cases, including 66 retirement cases. Native raw/RLS/
deferred guards, real waits and writer ordering, repeated evolution, retained
scope and drained roundtrip pass. Private database/role counts were `0|0`; the
server and its owned root were removed. No product migration, actual gate
change, physical action or demo has occurred. The
cutover record (private development evidence; not distributed) is
subcomponent evidence, not complete replacement or product acceptance.

### Internal replacement-aware recovery v2 — 6 October 2026

New accepted criteria explicitly bind old source, permanent retirement and
mapping review to an independently qualified current target. Original applied
mapping and later explicit historical revalidation are distinguished; existing
v1 policies never inherit replacement authority. Every mapping, even unused,
requires current peer scope/permissions, unrevoked acceptance and bounded expiry.

Read-only v2 proof retains old active/retirement provenance and counts only new
target quiet samples after all covered members' active/last-seen clocks. It
supports a quiet-only target without manufacturing an Alert, resets on bad
observations or gaps, and rejects stale/future or unprojected ingress, incomplete
coverage and exceeded bounds. Evidence references are non-material; closure
authority, causality and automatic-physical-truth flags stay false. Historical
policy detail and emergency withdrawal remain available after old origin/peer loss.

Additive migration `g1i3k5m7o9q2` preserves v1 history, guards native references,
actual role/scope and wall-clock expiry after waits, requires visible/drained
upgrade and refuses destructive populated v2 downgrade. Application checks still
perform full current origin/Worker attestation. Deployment examples default
`ICHECK_ENABLE_REPLACEMENT_RECOVERY=false`; the actual host is unchanged.

V2 recovery cannot authorize the existing v1 closure path. Coordinated compatible
proof/protocol/native handling, action-relative sampling and complete historical
direct/original/delegated/report readers remain next, followed by focused
replacement GUI/API and runtime-owned Agent retry/Worker-loss acceptance. The
full product's remaining live, fleet/load, identity/transport and accessibility
gates are unchanged; no integrated demo has run.

Final affected checks pass 322 ordinary and 461 migrated non-owner PostgreSQL
cases. A separate populated-v1 upgrade check passes on the same production code;
462 distinct native cases across those runs are not one full native-product
repeat. The private fixture objects/server were removed after `0|0` counts.
No frontend/browser/live acceptance was repeated. See the
v2 verification record (private development evidence; not distributed).

### Compatible replacement closure v2

Replacement-aware recovery can now feed an explicitly reviewed v2 closure
contract. Existing grants default to v1; new v2 review, claim and AI input must
select version 2. The receipt retains the v2 contract and unchanged stable
membership identity, preventing proof-version switches from authorizing another
closure of the same members. A separate default-off host flag protects rollout.

The checker locks and validates all current and historical mappings, including
unused policy bindings, before counting current-target quiet samples. Its floor
includes old active/last-seen clocks, the permanent retirement watermark and
actual terminal verification of every related action. Quiet-only targets need
no fake Alert, and old measured truth is preserved. Historical readers validate
typed complete references and both current/initiating read scope without fresh
old-origin or peer checks.

Native guards preserve v1 history and existing protections while validating v2
authority, exact receipt references, clocks and membership under the complete
producer prefix. Migration requires visible/drained ownership and refuses
destructive retained-v2 downgrade. A separate v2 AI Tool uses the owned journal
without rewriting installed v1 registrations, and closure web controls pin and
display the exact proof version. The following public workflow adds replacement
cutover API/GUI and owned Agent execution. Product migration/gate enablement,
actual new-Tool Worker-loss acceptance, deep history, production security,
sustained fleet/restart, live model/vendor and six-class GUI lab acceptance
remain required before the integrated demo.

The compatible closure component passes 455 distinct affected ordinary and 520
distinct affected migrated non-owner PostgreSQL cases across resumed runs,
including 40 ordinary/58 native new cases. These are not one wholly green
full-suite run or full-product acceptance. Frontend 39 unit cases, typing,
targeted lint and build pass; the private database/role/server fixture was
cleaned up. The
closure v2 record (private development evidence; not distributed)
retains the exact scope and remaining release gates. The full goal stays active.

### Native source evolution through the product — 8 October 2026

Collector evolution is now an in-product operation rather than an external
development/merge workflow. A focused source child page and typed API support
bounded discovery, exact intent, independent human acceptance, revocation,
explicit atomic retirement and scoped historical receipt recovery. Discovery
metadata is not current execution authority. Retirement preserves measured
history; quiet targets do not need artificial Alert episodes. No controls or
terminal tables are added to the AI-first home.

The L1 Agent can propose an equivalent generation mapping, wait for independent
human review, read fresh review metadata and explicitly apply the accepted
control-plane intent. These are separate typed internal Tools, not mandatory
external MCP servers or a hard-coded tool sequence. Fresh reads use a new
`check_key`; old read replay remains historical. Runtime-owned durable keys and
domain-first commits recover uncertain responses without repeating retirement.
The model cannot supply peer attestation or runtime write keys. Replacement,
recovery and reviewed incident closure remain distinct governed decisions and
default-off deployment boundaries, not proof of physical repair.

The focused GUI pins uncertain execution intent and clears private state on
namespace changes, including delayed responses. Original Investigation history
checks both initiating and actual reader scope over immutable source/retirement
references independently of registry edits. The subsequent delegated/runtime
boundary below covers source Task replay and actual process loss; retained report
proof and complete recovery acceptance remain open.

The final workflow has 30 focused ordinary and 26 migrated non-owner PostgreSQL
passes; frontend helper tests, typing, scoped lint and build pass. Browser
journeys use controlled API responses and do not accept live semantic truth or
production fleet capacity. The workflow record (private development evidence; not distributed)
separates final focused results from earlier affected regressions. The product
database and actual host gates remain unchanged. Complete current-product,
recovery, delegated/report, load/security and six-class GUI lab gates precede
the integrated demo.

### Delegated source recovery and execution finalization

Cached delegated results and bootstrap now recheck initiating/current retained
material scope. Replacement Task receipts must match immutable domain ownership,
the exact Tool journal and evidence bindings, even after registration changes.
Generic completion cannot forge an owned source result. Read-only context locks
are released before external model or checkpoint I/O.

Eight local native fault cases actually kill both Worker and API around source
proposal/application commits; a new Worker recovers after natural lease expiry
without duplicate retirement or altered measured history. This boundary requires
a nonterminal root checkpoint. Two additional actual Worker/API-loss cases prove
the existing scheduler reconciles committed terminal Investigation state before
execution acknowledgement without another attempt or model/Tool replay. Two
opposite ordinary/native cases reject checkpoint-only success. No second recovery
mechanism was needed; the final affected history/Worker/graph ordinary repeat
passes 43. See the finalization record (private development evidence; not distributed).
Affected ordinary checks pass 77 broader and 33 final targeted cases; native
verification has 45 distinct passes across two runs, not full-product acceptance.
See the runtime recovery record (private development evidence; not distributed).

Versioned retained-proof reports and closure runtime guards are implemented at
the boundaries below. Deeper history, current-product/security/load/rollout and
the user's GUI-onboarded lab must pass before the integrated demo. No product
database or actual host gate changed.

### Retained reports and closure journal safeguards

Reports can retain exact replacement, retirement and closure references with
scoped snapshots, original exports and scheduled inline/document delivery.
Saved evidence, delivery receipts, archive/purge and sparse discovery share the
current/frozen read boundary. Model prompts carry proof references, not private
delivery bodies. See [the report contract](docs/service-health-reports.md).

Both closure versions recover real API/Worker loss and truncated committed
responses while preserving the original journal, receipt and measured history.
Generic completion cannot overwrite owned claims/receipts after handler edits.
Cached Task results and terminal history require the exact immutable receipt
and citation binding. Running commit gaps remain resumable. Root invocation and
resume synchronously acknowledge checkpoints before Tool dispatch, preventing
an independent domain commit from outrunning its durable next step.

The journal verification record (private development evidence; not distributed)
retains affected ordinary and non-owner native boundaries, including the actual
checkpoint-ordering failure and subsequent recovery. These are component
results, not whole-product, production or lab acceptance. Existing native
Prometheus/SNMP services are active/enabled and locally healthy. Current-product
acceptance, packaging/restart/load, drained rollout, production identity/transport
and real six-class GUI onboarding remain required before the integrated demo.

### Native test release and authenticated browser checkpoint — 9 October 2026

At this checkpoint the local candidate was r21: an installed-wheel backend, 72 pinned
runtime dependencies, standalone Node 22 frontend and bundled native operator
files. Its backend is unchanged from r20 and directly matches all 452 current
backend/migration/resource files. Complete ordinary and native PostgreSQL
commands exited zero at that source boundary; collected counts are not pass
counts and the native scale opt-in remains skipped.

The actual required-auth browser custody path now passes against a migrated,
non-owner PostgreSQL runtime. The UI recovers one unresolved record after an
injected gateway error following commit, keeps the same request identity on
retry, and preserves the unknown original write. Requester self-review and
missing-CSRF mutation are rejected. This acceptance uses seeded unknown-write
state, empty evidence and loopback HTTP; live provider/recipient truth and
production TLS/identity remain separate requirements.

r21 also makes the AI home respect account permissions when loading data and
offering creation or cancellation. Reviewers keep their authorized evidence
connected without requesting AI configuration they cannot read. An
investigation-only reader sees unavailable inventory/Worker data, while an
operator retains profile selection and the objective composer. Real sessions,
narrow rendering and sign-out are recorded in the
current release checkpoint (private development evidence; not distributed).
The host still lacks the active backend/13 required units and staged frontend,
and its frontend unit resolves Node 18. Broader accessibility/privacy, native
installation/restart, provider/recipient and conflict handling, production
transport/load and the user's six-class GUI lab remain unfinished. These gates
precede the integrated demo.

### Staged native r23 checkpoint — 9 October 2026

The latest candidate is r23. Its backend is now installed offline in a sealed
versioned host virtualenv, with all 72 pins, 24 callable commands and 452
wheel-owned files verified. The dedicated `icheck` account can read/execute
the packaged migration CLI and passes `pip check`. Node 22.23.3 is separately
installed; global Node was not changed. The frontend has a guarded active
release pointer and a real strict systemd unit whose start/restart/clean-stop
acceptance passes. Normal Next.js SIGTERM cleanup is explicitly recognized as
exit 143; failed/transitioning units cannot pass the corrected host gate.

Mobile home navigation is now a focus-isolating modal, with keyboard/dismissal,
responsive resize, routing and real sign-out accepted through actual required
sessions and disposable non-owner PostgreSQL. The r23 application packages are
unchanged from the tested r22 frontend and r20 wheel; only the two operator
corrections required a refresh. The
r23 record (private development evidence; not distributed) separates these
accepted components from the remaining product rollout.

The frontend is intentionally stopped and disabled. The backend pointer,
product PostgreSQL/checkpoint deployment and 13 required backend units are not
active. Broader browser privacy/accessibility, live provider/recipient/conflict
qualification, production identity/transport/secrets/load and the six-class
GUI lab remain open. Existing Prometheus/SNMP exporter stay active and healthy.
An installed frontend component is not the integrated product demonstration;
that demonstration still waits for the complete acceptance gates.

### Native r25 database/API and first-release boundary — 9 October 2026

The design remains an in-product, user-extensible IT Agent, not an NMS chatbot.
The original requirements are represented in code: alert/incident evidence;
persisted device IP/MAC and wireless terminal observations; a permission-aware
AI operator home with separate Assets/Endpoints/Topology; server-side AI model,
URL and credential configuration; an iterative checkpointed LangGraph Tool loop;
typed internal Tools plus governed external MCP integration; and in-product
collector, workflow, Skill, Tool and visualization authoring/review/versioning.
Device onboarding is through `/assets/devices`; endpoints and workflow templates
remain separate `/assets/endpoints` and `/studio/workflows` surfaces. Presence in
code is not acceptance of a live model, physical device or production capacity.

r25 now has actual native PostgreSQL, restricted runtime/checkpoint roles,
installed-wheel migration, backup/logical restore and guarded backend selection.
The real four-worker API and unchanged frontend pass component start/restart/
clean-stop under the dedicated service account. Required authentication and
checkpoint verification stay on; reviewed actions stay off. A checkpoint-owner
TEMP preflight, consistent production environment templates and dedicated Node
drain compatibility close real installation gaps. Prometheus/SNMP exporter remain
installed, active and healthy without Docker.

API/frontend are stopped and disabled pending the complete rollout. Remaining
release gates are trusted TLS/browser identity and Worker mTLS/credentials;
twelve native Worker services and internal table grants; broader browser privacy/
accessibility/revocation; live provider/recipient/vendor/Windows and optional
Ansible qualification; representative sustained load and production recovery;
then the user's six-class GUI-onboarded lab. Only after code freeze and those
acceptance gates pass should the integrated demo run. The
r25 evidence (private development evidence; not distributed) distinguishes
installed components from these unfinished requirements.

### Native r28 internal-controller boundary — 9 October 2026

The first internal database-controller profile is now implemented and verified
for lease reconciliation. Separate database/OS identities, insert-only audit,
nine readable tables and 35 named runtime UPDATE columns allow lease cancellation,
canary failure and activated-device health without granting device identity,
collector configuration, approval, secrets or DDL authority. Inspection is
read-only; owner-managed provisioning requires explicit acknowledgements and
rolls back partial failure. Unknown profiles and excess authority fail closed.
These are trusted internal-core actors, not tenant-delegated logins; generated
capabilities and remote Agent/Collector/Attestor Workers must not receive these
DSNs. Application session namespace/RLS remains separate from credential custody.

The actual isolated reconciler performs stable idle cycles, restarts and stops
cleanly. Cross-account filesystem probes deny credential reads in both directions.
Fifteen native permission/workload cases and focused ordinary/settings checks
pass; 453 current payload files match the installed r28 wheel. Settings errors
hide secret-bearing input maps. The guarded backend pointer now selects r28;
r26/r27 were never selected. See the r28 record (private development evidence; not distributed).

Eight other direct-database profiles and credential isolation for other Workers/
frontend remain code and rollout work, not merely missing lab inputs. Eleven
Worker services and populated restricted-role recovery remain unaccepted.
TLS/browser identity, remote mTLS, broader browser/provider/vendor/Windows/load/
production recovery and six-class GUI onboarding remain open. API, frontend and
lease controller stay stopped/disabled; database and monitoring remain locally
active. No whole-product acceptance or integrated demo is claimed.

### Native r29 component identity boundary — 9 October 2026

The native design now mandates OS credential custody per trusted component.
Frontend, monitoring, remote Workers, internal controllers, capacity management
and optional action/attestor services do not share API UID or group. Agent/
Collector capacity instances share only their respective database-free pool
identity. Accounts are non-root/non-login, state directories private, and
certificate/token/config paths readable only by the appropriate component.
The SNMP attestor's explicit exporter-config read is not API access. This
component boundary does not replace tenant RLS or generated-capability sandboxes.

The capacity controller is unprivileged and receives only exact configured
instance start/stop authorization through an operator-reviewed policy. It cannot
restart arbitrary services, alter unit files, create transient units or fall
back to root. The root deployment operator retains account, config, unit and
policy installation authority, never the AI loop or generated artifacts.

All twenty templates use eighteen approved identities; actual account inspection
passes. The frontend and installed Prometheus/SNMP Exporter now pass separate-UID
native checks. TSDB/target lists remain retained and fifty cross-component read
probes are denied. Real capacity permission tests pass against temporary sleep
units, then remove those fixtures/policy. The guarded backend selects r29 at the
unchanged migration head, with all 453 payload files matching current wheel
bytes. See the r29 record (private development evidence; not distributed).

Eight internal DB profiles, eleven remaining Worker units, per-component
production credentials/certificates, populated recovery/drain and actual capacity
receipt/convergence/scale-in remain code and acceptance work. Production browser
identity/TLS/mTLS, broader browser/provider/vendor/Windows/load/recovery and the
normal-GUI six-class lab remain open. There is no production capacity rule or
integrated demo; installed product services remain stopped/disabled.

The GUI-only onboarding requirement includes continuous metrics enrollment and
withdrawal, not merely bounded collector previews. The native file-discovery
lists currently remain operator-provisioned; a scoped, authenticated discovery/
publication contract and revision/revocation/restart acceptance are still needed.
Keep that publication boundary separate from API credentials and monitoring
config ownership. Remote-write registry metadata does not configure ingestion.

### Native r30 Projection/Indicator boundary — 9 October 2026

Projection and Indicator now follow the reviewed core-controller SQL boundary,
with 43/11 explicit relations, named runtime column updates and separate OS/
database identities. Inventory, Wi-Fi terminal history, alerts, topology,
collector conditions and derived indicator publication remain supported under
those grants. Device/source identity, credential references, queries, thresholds,
approval/publication configuration, deletion and DDL are not writable. Reference
row locks use explicit timestamp UPDATE grants; those are real timestamp writes,
not pure SELECT permissions. The roles belong only to trusted core components,
not users, remote Workers or generated capability processes.

Indicator upstream I/O holds no row locks. After it returns, the worker locks
and revalidates lease ownership and the binding/definition/backend revisions.
Observation, audit and terminal completion commit together. A stale lease,
changed configuration, unsupported PostgreSQL transaction mode or fault after
observation flush cannot publish a partial result. Secret values come from the
worker's own resolver/custody boundary, not configuration rows or API credentials.

Populated disposable-PostgreSQL checks kill real source Worker subprocesses,
wait for natural 15/30-second leases, replace them and restart idempotently.
Actual native systemd checks separately verify exact installed grants, empty
polling, UID, private state, restart and clean stop. Ten cross-account credential
read attempts fail. The guarded backend selects r30 with unchanged head, frontend
and dependency pins, and all 453 payload files matching its wheel. See the
r30 record (private development evidence; not distributed).

Six direct-DB profiles and nine Worker units remain unfinished. Populated
installed-host/drain/capacity/load, production credentials/TLS/browser identity/
remote mTLS, broader browser/provider/vendor/Windows/recovery and automatic GUI
continuous-scrape enrollment remain explicit gates. All five installed product
services are stopped/disabled; native database and monitoring remain active.
No live-device evidence, whole-product acceptance or integrated demo is claimed.
