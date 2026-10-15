# MVP architecture

## Product boundary

The target preview is an AI operations agent for network, system and DevOps
engineers. iCheck owns the operational workflow, Prometheus owns time-series
collection/storage, and Grafana owns monitoring visualization. The
[12 October goal](codex-goal.md) replaces the old custom metric UI and Service
Intelligence priorities. Reuse existing inventory, alerts, credentials,
collectors, monitoring gateway and LangGraph foundations.

```text
Conversation → bounded LangGraph tools and workflows
                   ├── query evidence and investigate
                   ├── Studio: describe → preview → test → enable
                   │     ├── exporter/adapter → Prometheus
                   │     └── dashboard definition → Grafana
                   └── explicitly approved operational action

Prometheus → Grafana metric dashboards
Inventory collectors → PostgreSQL identity, IP/MAC and Wi-Fi histories
```

There is no second React charting engine or time-series database in iCheck.
Keep supporting device, terminal, alert, evidence and configuration pages.
Remove Services from the UI without destroying historical records. Replace
the complex Studio with one conversation-first builder. See
[integration ownership and deployment](grafana-monitoring-design.md).

Start Grafana with a native HTTP adapter and authenticated contextual links.
Local adapters and optional MCP share one Tool Registry contract; not every
plugin needs its own server. A trusted lab workspace is the preview scope, not
multi-tenant Grafana authorization. Detailed service-specific contracts below
record legacy implementation, not requirements to complete before the preview.

## Native release boundary

The 14 October multi-provider source update generalizes guided AI configuration
beyond OpenRouter. Fixed-origin presets select the native/compatible protocol;
key custody, model identity and purpose routing stay separate reusable records.
Operator, dashboard AI and Studio share adapters, local result validation and
quotas. Connecting a provider never silently changes routes. Private gateways
and environment/Vault references remain optional Advanced configuration.
This update is not deployed; see the [provider guide](ai-multi-provider-setup.md).

The non-container server target uses an installed Python wheel and a standalone
Node.js frontend behind the trusted TLS ingress, with independently deployed
systemd Workers. The frontend package carries its server/dependencies/assets
and binds loopback; `/api/v1` routes directly to the API. The wheel's operator-only
`icheck-db` command runs its bundled migrations without a source checkout,
requires an explicit database URL and confirms coordinated drain before upgrade.
Migration guards and production identity requirements remain unchanged. Hosted
frontend commands are retained as a separate target. See [native release](native-release.md)
for package, ingress, restart and acceptance requirements.

Engineering Preview v0.1 keeps the AI operator home separate from supporting
inventory and alert pages. Installation ships parameterized HTTPS, first-login
and local monitoring helpers; it does not bake the development server's LAN
addresses into new installs. The administrator selects server interfaces,
finite read-only collection ranges and external secret custody. Collector and
Agent use separate mTLS identities and have no database credentials. Prometheus
and SNMP Exporter remain native, separately isolated processes. Grafana is the
next native service, behind HTTPS with its own data directory and sign-in. Adding
visualization must not change existing collection approvals or TSDB data.

AI settings has a guided OpenRouter adapter as well as advanced external-secret
references. The GUI accepts a write-only API key over HTTPS, stores authenticated
ciphertext in namespace-scoped SQL using a separately provisioned server key,
and records exact provider-bound egress approval. Both the LangGraph reasoner
and structured-authoring gateway enforce that approval at request admission.
Keys remain in the API boundary, never the Collector/Agent configuration. See
[AI provider configuration](ai-provider-configuration.md) for custody and recovery.

Package checks, a clean operating-system installation rehearsal and the user's
real-lab GUI acceptance are separate evidence boundaries. Built-in capability
bootstrap must not create pretend devices or source observations. The user owns
EVE-NG connectivity and GUI onboarding; live metrics, source-derived topology,
alerts, AI conclusions and custom extensions cannot be claimed from an empty
inventory or a successful login alone.

## Endpoint identity model

A MAC address identifies an endpoint record. Mutable facts are stored as
time-bounded observations rather than overwritten fields.

```text
Endpoint (normalized MAC)
  ├── IP address observations
  │     source, collector, VLAN, first_seen, last_seen, active
  ├── wired attachments
  │     switch, interface, VLAN, first_seen, last_seen, active
  └── wireless sessions
        controller, AP, SSID, IP, radio, signal, connected/disconnected
```

This supports current-state and historical questions:

- Which MAC currently owns an IP?
- Which IP addresses has this endpoint used?
- Which switch port or AP last observed it?
- When did a wireless client roam or disconnect?
- Did an IP change occur near an incident?

The `raw_data` JSON fields retain unmodeled vendor fields while stable fields remain
indexed and queryable. Vendor adapters should not place credentials in raw data.

## Alert lifecycle

```text
Observation or external event
        ↓
Enabled matching rule
        ↓
Deterministic condition check
        ↓
Deduplication key
        ↓
OPEN → ACKNOWLEDGED → RESOLVED
```

Repeated matching observations update `last_seen` and `occurrence_count` on the
same active alert. A later recovery observation may resolve it automatically.
Manual acknowledgement and resolution always record the actor and timestamp.

Initial built-in rule types:

- `wireless.rssi.low` — threshold defaults to `-75 dBm`.
- `endpoint.ip.changed` — emitted when an active address changes for the same
  endpoint, source, collector, and IP family.
- `endpoint.new` — available but disabled by default to avoid initial discovery
  noise.

## Situation boundary

```text
Distinct active Alerts on an exact entity, unambiguous reviewed-service components,
or one fresh evidence-qualified topology adjacency
        ↓
same_entity/v1 → reviewed_service/v2 → qualified_topology/v3 grouping
        ↓
OPEN → ACKNOWLEDGED → RESOLVED
        ↓
preserved Alert evidence + ordered lifecycle timeline
        ↓
durably bound AI Investigation
```

Situation state does not replace Alert state. A repeated occurrence stays on
its existing Alert and updates aggregate Situation counts; a new Alert adds a
membership and reopens acknowledged attention. All member Alerts must resolve
before the Situation resolves. The partial unique correlation index and a
PostgreSQL advisory transaction lock prevent two live Situations for the same
correlation key. Reviewed-service grouping requires one active catalog match;
qualified-topology grouping requires one candidate Situation and active,
allowlisted, fresh one-hop evidence. The topology membership is frozen at
`0.70` confidence with `causal_claim=false`; no policy infers root cause across
entities.

External incident delivery is separated from local lifecycle truth. A pinned
MCP Tool may create one schema-derived remote reference. Ed25519-authenticated
callbacks may update only that reference and append an observed-status event;
they cannot acknowledge, resolve, or otherwise transition the Situation.

Manual lifecycle mutations now lock and refresh the Situation, require a real
READ COMMITTED PostgreSQL transaction, and recheck the authenticated caller's
complete current scope after waiting. Resolution counts authoritative joined
Alert rows, not cached counters or membership status snapshots; empty or hidden
sources and unpersisted Alert/membership edits are refused. A successful manual
resolution refreshes the summary and records exactly one explicit manual event
and audit. A later existing-membership correlator refreshes current sources and
reopens an active projection; ingestion after a committed quiet closure can
create a new generation. No reversed parent-to-Alert row lock is introduced.

This ordering covers the supported correlator/lifecycle paths, not arbitrary
raw SQL that bypasses them or every source-ingestion race. Both manual and
automatic all-Alert-state resolution explicitly record
`independently_verified=false` and `authorizes_ai_closure=false`. Neither is an
immutable independent remediation proof. Verified AI closure and fresh
deduplication/source-observation writer acceptance remain separate code gates.
See the local record (private development evidence; not distributed).

## Service boundaries

```text
Distributed collectors / vendor adapters
        ↓
Normalized ingestion contracts
        ↓
Immutable staging + leased Knowledge Projection Workers
        ↓
Inventory + alert + Situation domain services
        ↓
PostgreSQL
        ↓
Typed capability APIs
        ↓
LangGraph Agent Runtime
        ↓
AI L1 workspace / Capability Studio / supporting subpages
```

SNMP, WLC, arbitrary APIs, Prometheus, and WMI/CIM collectors must translate
source data into the same ingestion contracts. They must not write directly to
database tables or cause source-specific fields to spread through the core
domain model.

Explicitly versioned projection contracts, not source adapters, translate
eligible envelopes into operational knowledge. Unsupported types remain
immutable staging evidence. Projection ownership and domain writes are
transactional, horizontally claimable through PostgreSQL leases, and scoped by
the originating CollectorDeployment.

Low-cardinality API/Collector/business indicators reuse this boundary through
`icheck.service-indicator-observation/v1`. An exact published Collector version
and stable binding key select the reviewed indicator contract; the projection
transaction writes the observation and immutable Artifact/binding/envelope
provenance together. Scheduled Workflow publication is a separate governed path:
an exact published Workflow version maps one pinned read-only Tool's typed
result, never model prose, to the observation while preserving Investigation and
ToolCall provenance. Neither path adds a credential-bearing generic scheduler
to the service catalog.

The generic `icheck.knowledge.entity/v1` and
`icheck.knowledge.relationship/v1` contracts let user-created collectors add
new typed nodes and edges without a core schema release. Artifact-derived
namespaces, deployment scope, bounded normalized attributes, deterministic
identity, and out-of-order non-regression prevent this extension boundary from
becoming arbitrary database access. Specialized endpoint, Wi-Fi, and Alert
projections remain first-class domains where richer lifecycle behavior is
needed.

The Agent Runtime uses typed capability APIs over these services. It does not
receive database, model-provider, or infrastructure credentials.
Its built-in `knowledge.query_graph` capability provides a scoped, minimized,
one-hop view of user-created Entity/Relationship knowledge; open-ended
multi-hop reasoning remains bounded by repeated tool calls and Investigation
budgets rather than direct database traversal.

Published `icheck.topology/v1` Artifacts are a separate read-only consumer of
the same normalized knowledge. The runtime revalidates the immutable contract,
then applies `assets.read` and the caller's device/site predicates inside the
device, endpoint, Entity, and Relationship queries. It returns a bounded,
minimized live graph to `/topology`; Studio validation previews are never used
as runtime state.

## Generic collector contract

A collector is a versioned artifact with connection metadata, schedule or event
mode, normalized outputs, rate limits, health checks, permissions, test
fixtures, and a credential reference.

Collection workers register with the control plane and use leases and
heartbeats. Target ownership can be reassigned without duplicate uncontrolled
polling. Workers apply retry budgets, jitter, timeouts, per-target concurrency,
and backpressure.

SNMP Exporter, controller APIs, HTTP APIs, windows_exporter, and on-demand
PSRP/CIM are initial collector or diagnostic packs, not hard-coded platform
boundaries.

## AI and workflow runtime

LangGraph is the initial orchestration choice. Known runbooks use deterministic
graphs; uncertain troubleshooting uses a bounded plan → tool → evidence →
evaluate loop. Both persist the same investigation state and can pause for
human approval.

Every run records its purpose, entity scope, evidence, hypotheses, tool results,
budget, approval state, conclusion, and escalation reason. Loops have explicit
iteration, duration, cost, duplicate-call, and target-rate limits.

An opted-in state-changing Tool adds a second, evidence-gated boundary:

```text
exact action proposal
        ↓
frozen change plan + target + Tool/schema versions + idempotency hash
        ↓
pre-check + dry-run + maintenance window
        ↓
two-person, dual-hash approval
        ↓
execution-time drift/window recheck
        ↓
post-check → verified   OR   rollback evidence
```

The runtime executes the frozen read-only pre-check and dry-run before the
interrupt, reuses their persisted calls after resume, and runs the frozen
post-check after action success. Rollback has separate state-changing authority,
not an automatic continuation of the original authorization. Its proposal
carries the parent change-plan ID and requires its own peer decision or a
distinct independent restoration grant. Both automatic host switches default
off. Recovery admission serializes on that failed parent, owns at most one
write slot without refunding its original Alert debit, and rechecks current
authority before execution-start. An uncertain write cannot replay. Optional
typed restoration evidence verifies original state but does not mark the failed
primary purpose successful or close an incident. See
[the separate authority contract](./reviewed-change-preapprovals.md#independent-rollback-qualification-and-one-shot-recovery).

The plan records minimized hashes and references, not credentials. It does not
make model output an execution fact. Tools without this v1 contract remain on
the legacy approval kernel and are not production change adapters.

MCP is used for focused external or user capability packs. Core typed tools may
run in process, while distributed collectors and action workers use internal
HTTP/gRPC contracts. MCP is not required for every function.

Distributed Worker HTTP contracts use bearer credentials plus a separately
verified client-certificate identity. A private trusted proxy strips untrusted
certificate headers, verifies the Worker CA chain, and forwards the bounded
SHA-256 identity contract. Registration binds that identity; every subsequent
route requires both factors. Rotation is staged and promoted by first eligible
use, with optimistic cancellation and emergency revocation. See
[`worker-mtls.md`](./worker-mtls.md).

## Generated artifact lifecycle

Report artifacts have two explicit contracts. Metric-only v1 remains compatible;
v2 adds exact typed references to retained replacement requests, source retirements
and closure receipts. V2 allows proof-only reports without inventing healthy
metrics, or at most 12 metric selectors within a shared 20-section budget.
Trusted code resolves immutable records, not model-authored proof narratives.

Saved v2 reports store an independent initiating-reader admission and exact
foreign-key references. Current persisted read roles and current/capture-time
scope apply to historical reports, exports, attachments and Agent evidence.
Retained proof is not fresh execution permission, repair causality or automated
physical truth. AI Studio receives selected kinds/IDs only; a core internal Tool
returns bounded proof identities/citations. These functions do not require an
external MCP server. V1 bytes are unchanged. Scheduled v2 delivery now captures
an exact saved snapshot and evidence link before dispatch, using a typed inline
input or a document manifest. Every bound send, verification and rollback Tool
rechecks current authority and exact input. V3 delivery receipts also pin inline
snapshots and cannot bypass their read scope. Independently reviewed archive
purge removes report copies, not their domain proof. Candidate discovery is
bounded and publishes only authorized cursors; sustained load, live transport
qualification and v2 production rollout remain separate release gates.

Workflow model context carries only retained-report references and historical
flags, not the private delivery snapshot. Every model turn rechecks the saved
evidence binding and current read scope. Fixed delivery still uses the original
approved body; nested-field consumers have the same read boundary.

Reviewed closure recovery keeps one runtime-owned journal and operation across
API/Worker loss. A still-live claim produces a typed bounded wait, with
lease-only renewal and cancellation checks rather than a second token. After
expiry, takeover revalidates fresh authority; an already committed receipt is
read-only history. Tool-only response-loss retries preserve any recorded MCP
resume and do not repeat external execution. Both proof versions have isolated
non-owner PostgreSQL process-loss and truncated-response acceptance. Coordinated
API/Worker upgrade is required; production HTTPS/mTLS, proxy/load and rollout
acceptance remain separate. See
[the closure runtime contract](agent-runtime.md#reviewed-situation-control-plane-tools).

Owned closure journals cannot be completed through a generic Tool API. Current
handler edits do not erase immutable ownership; success requires the exact
receipt and citation. Cached runtime/history reads retain that same equality
boundary. Root checkpoint acknowledgement precedes Tool dispatch on both invoke
and resume, so an independent domain commit cannot outrun its resumable root
step. These safeguards do not grant fresh execution authority or qualify a
production rollout.

```text
draft → validate → sandbox test → preview → review → publish
      → scoped deploy → observe → revise or roll back
```

Published artifact versions are immutable and exportable. Conversation history
alone is not an executable specification. Collectors, mappings, tools, skills,
workflows, topology definitions, and generated views must carry their schemas,
tests, dependencies, permissions, and version history.

## Deployment boundary

Docker Compose is only a local development convenience. The production baseline
uses independently deployable control-plane services, site or regional
collector workers, knowledge-projection workers, service-indicator workers,
and execution workers on VMs or bare metal under systemd.
Containers remain optional.

Every production process is pinned to one tenant and region. User requests
resolve a fixed-tenant principal plus an allowed active region; ORM predicates,
write guards, and PostgreSQL row-level security enforce the same boundary.
Regional scaling controllers observe Collector and Agent queues and persist
bounded desired-replica decisions. They never provision or terminate hosts;
an operator-owned capacity provider may reconcile those decisions to systemd,
VM, bare-metal, or optional orchestrator APIs.

Browser operators sign in with username/password by default. Local human
passwords use salted, versioned slow hashes, while existing HttpOnly cookies,
CSRF checks and Principal role/scope enforcement remain the session boundary.
API and worker token authentication is separate; no token input appears in the
web login form. Administrators provision/reset passwords in identity settings;
users change their own password in account settings. Password changes revoke
browser sessions, not API tokens. Optional SSO may use prebound enterprise OIDC
Authorization Code/PKCE.
The identity provider proves authentication only; iCheck Principal bindings,
tenant/region placement, local roles, scopes, approvals, and audit remain the
authorization boundary. Provider groups never create roles, and provider
tokens and raw subject/claim values are not retained.

PostgreSQL stores knowledge, configuration, alert/incident state, artifact
metadata, workflow checkpoints, and audit records. Metrics belong in a
Prometheus-compatible time-series plane; logs and large artifacts use their
appropriate stores.

Low-cardinality service evidence is materialized by a dedicated, horizontally
scalable PostgreSQL-leased Indicator Worker. It queries only registered Metric
Backends through the shared host-allowlisted Prometheus client, applies an
explicit bounded scalar reduction, and writes an idempotent observation. Raw
time series remain in the metrics plane; the knowledge store contains only the
governed definition, run health, evidence reference, and reduced sample.
Metric and Loki query clients share an explicit backend-authentication boundary:
none, bearer, basic, or a validated custom header. Authenticated requests resolve
one adapter-authorized, non-Worker-scoped Credential Profile value just in time;
resolved values are never returned or persisted and are redacted from upstream
failures. Operators own these connections at `/settings/observability`.

## Next architectural slice

The accepted order is:

1. Artifact and generic collector contracts.
2. Distributed collector registration, authenticated worker identity, leases,
   schema validation, audit, health, and a reference API collector.
3. Prometheus, SNMP, windows_exporter, governed PSRP/CIM, and authenticated
   Prometheus/Loki query boundaries are implemented; representative
   non-container device and production-secret-provider validation are next.
4. AI provider/model configuration, secret references, and Tool Registry
   contracts.
5. Durable LangGraph investigation state and a read-only agent loop.
6. AI L1 information architecture and conversational Capability Studio.

See [the development plan](./development-plan.md) for status and exit criteria.
