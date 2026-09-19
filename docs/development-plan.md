# iCheck development plan

## North star

iCheck is an AI-native, self-extensible IT operations agent platform. It is not
a traditional monitoring product with a chatbot or agent attached to it.

The AI Agent Runtime is the product kernel. Users investigate infrastructure and
create missing platform capabilities through the same in-product conversation.
Collectors, parsers, topology views, tools, skills, workflows, visualizations,
and reports are versioned artifacts that can be generated, tested, published,
observed, revised, exported, and rolled back without a separate IDE or vendor
release.

This plan is subordinate to the architectural rules in
`iCheck_project_design.md`.

## Planning principles

1. Build the agent kernel and Capability Studio before growing a broad catalog
   of conventional monitoring screens.
2. Treat every source protocol as an adapter behind a generic collector
   contract. SNMP is one built-in pack, not the platform boundary.
3. Use deterministic workflows for known runbooks and bounded agent loops for
   open-ended troubleshooting.
4. Keep model providers, tool transports, collectors, and execution engines
   replaceable behind iCheck-owned contracts.
5. Generated artifacts never receive production credentials and never
   self-publish. Deterministic validation and policy own that transition.
6. Keep Docker Compose for development and demonstration. Production must
   support independently scalable VM/bare-metal services and site collectors.
7. Every release must expose evidence, audit, health, and rollback appropriate
   to its operational risk.

## Status legend

- **Complete**: implemented and verified in this repository.
- **Next**: committed next milestone.
- **Planned**: accepted scope with an upstream dependency.
- **Later**: deliberately deferred until safety and scale foundations exist.

No calendar dates are assigned until team capacity and target environments are
known. Milestones are ordered by product dependency rather than elapsed time.

## Current baseline

### M0 — Runnable vertical slice

Status: **Complete**

Delivered:

- PostgreSQL-ready entity and endpoint identity model.
- Historical IP, MAC, wired attachment, and wireless-controller terminal data.
- Alert rules, deduplication, acknowledgement, recovery, and resolution.
- Collector-facing normalized ingestion contracts.
- Initial API and operations UI.
- End-to-end API tests and local development packaging.

Explicitly not delivered as part of the M0 release itself:

- LangGraph or a functioning AI agent runtime.
- AI provider, model URL, model name, or token-reference configuration.
- MCP server platform.
- Prometheus, SNMP Exporter, windows_exporter, or WMI/CIM execution adapters.
- Production deployment or capacity validation.
- In-product capability authoring.

## Accepted design decisions

| Area | Decision |
|---|---|
| Product identity | AI IT operations agent and capability platform, not NMS plus AI |
| Primary interaction | AI L1 operations workspace and conversational capability creation |
| Extensibility | Users create collectors, topology, tools, skills, and workflows inside iCheck |
| Artifact safety | Typed, versioned, tested, approved, scoped, observable, and reversible |
| Collection | Protocol-neutral collector contract with distributed workers |
| Agent orchestration | LangGraph hybrid of deterministic graphs and bounded agent loops |
| MCP | Supported at plug-in and integration boundaries; not required for every tool |
| UI | Situation- and AI-first home; raw inventory and terminals use subpages |
| Secrets | Secret references only; models never receive credentials |
| Deployment | Docker Compose is development-only; production does not require containers |
| Metrics | Prometheus-compatible regional collection and scalable remote storage path |
| Windows | Continuous metrics plus governed on-demand PSRP/CIM diagnostics |

## M1 — Distributed collection and data foundation

Status: **In progress**

Progress:

- Implemented generic Artifact and immutable ArtifactVersion models.
- Implemented collector definitions, deployments, worker registration,
  heartbeats, selectors, atomic leases, lease renewal, run history, and health.
- Implemented Entity/Relationship/Observation/Event staging envelopes with
  idempotency.
- Added the standalone `http_json` worker, outbound host allowlist, and systemd
  service template.
- Added and verified the M1 database migration and end-to-end control-plane
  tests.
- Added bootstrap-authenticated worker registration, per-worker bearer tokens,
  token rotation, and worker-plus-lease authorization for run operations.
- Added credential profiles that store only external secret references, enforce
  adapter and worker scope, and expose a fail-closed worker-side broker contract.
- Added bounded JSON Schema validation for generated collector target and
  configuration contracts. Remote references, oversized schemas, and excessive
  nesting are rejected.
- Added durable audit events for artifact, credential, deployment, worker, and
  collector-run lifecycle actions.
- Added a provider-neutral metric backend registry with bounded Prometheus
  instant/range queries, remote-write endpoint metadata, health state, host
  allowlists, and query-hash audit.
- Added the versioned built-in SNMP Exporter collector pack, Prometheus-text
  normalization, exporter/target allowlists, and non-container systemd/config
  templates.
- Added a versioned windows_exporter pack, bounded preview adapter, Prometheus
  target discovery, and a restricted collector baseline.
- Added deployment-scoped credential references and explicit `scheduled` versus
  `on_demand` execution. On-demand runs return to an unscheduled state after
  completion and require an audited trigger reason.
- Added the PSRP/CIM diagnostic pack with fixed read-only CIM operations,
  WinRM-TLS policy, target allowlists, response budgets, and fail-closed external
  credential-executor boundary.
- Installed and validated Prometheus 3.13.3 LTS and SNMP Exporter 0.30.1 on the
  representative Ubuntu host without Docker. Both services use the dedicated
  `icheck` account, loopback-only listeners, protected configuration, systemd
  startup, and bounded local retention. Config validation, self-scrapes,
  bounded PromQL, and restart recovery passed.
- Added a dedicated web device-onboarding workflow and protocol-neutral Assets
  API. Operators can register network, controller, Linux, Windows, and other
  targets; declare SNMP, HTTPS API, SSH, windows_exporter, WinRM HTTPS, and ICMP
  connection intents; attach site-scoped credential references; and search the
  resulting inventory without placing raw inventory tables on the AI home.
- Added transactional device/connection persistence, duplicate and scope
  validation, secret-shape rejection, immutable onboarding audit evidence, a
  clean Alembic migration, and end-to-end API coverage. New connections remain
  pending until worker verification; configuration is not reported as live
  monitoring.
- Added authenticated, leased device-preflight claim/report contracts with
  site and adapter-capability matching, lease expiry/reassignment, bounded and
  secret-checked evidence, immutable attempt history, explicit operator retry,
  device readiness aggregation, and a response-bounded history API.
- Connected the standalone worker to the preflight loop. ICMP performs a
  bounded echo, HTTP/SSH/Windows connections perform allowlisted TCP transport
  checks without claiming authentication, and SNMP performs a bounded query
  through the site-local SNMP Exporter. Results and failures are visible in the
  Assets page with audit evidence.
- Added versioned device-activation policies with draft, validation,
  publication, previous-version deprecation, deterministic placeholders, and
  collector-schema validation. Verified connection intent is rendered into a
  previewable deployment plan whose immutable hash must be approved.
- Added atomic, idempotent activation and audited deactivation. Activation
  reuses the collector control plane, enforces artifact publication,
  protocol/adapter compatibility, credential and worker scope, and leaves
  deactivated deployments disabled with history intact.
- Added published built-in activation policies for SNMP Exporter,
  windows_exporter, and on-demand PSRP/CIM. The Assets page supports policy
  selection, plan/warning preview, reasoned approval, and reasoned deactivation.
- Verified the activation slice with a clean full migration, idempotent seed,
  TypeScript/lint checks, and a production frontend build.
- Added persistent activation runtime health and approved-deployment
  fingerprints. Worker polling and run completion reconcile first success,
  consecutive failure, freshness, missing/disabled deployments, and content
  drift into explainable connection and device states.
- Added promotion from `monitoring_configured` to `active` only after fresh
  successful scheduled runs; failed/stale collection becomes `degraded`.
  Re-approving the unchanged plan repairs drift atomically and resets health for
  fresh acceptance. The Assets page exposes status, reason, timestamps, failure
  count, and repair preview.
- Verified the combined activation and runtime-health slice with a clean
  migration through `e84b7a2d19c3`, idempotent seed, 38 backend tests, and a
  Node 22 production frontend build.
- Added persistent control-plane principals, built-in and custom roles, scoped
  role bindings, one-time bootstrap, hash-only revocable access tokens, and
  audited identity administration. Production refuses to start with
  control-plane authentication disabled.

Remaining before M1 exit:

- mTLS/certificate identity, browser OIDC/session integration, and RBAC/scope
  enforcement across every legacy control-plane route.
- External credential-provider adapters and short-lived worker-side resolution.
- Isolated sandbox execution for generated implementations and fixtures.
- Real-device SNMP positive/negative target validation, remote-write backend
  validation, cardinality controls, and scale evidence.
- Live windows_exporter installation and an external credential-provider-backed
  PSRP executor.
- Multi-worker failure, scale, queue-lag, and 1,000-target load tests.

### Scope

- Define `Artifact`, `ArtifactVersion`, `CollectorDefinition`,
  `CollectorDeployment`, and `CollectorRun` contracts.
- Support poll, event, and stream collection modes.
- Build a worker scheduler with leases, heartbeats, jitter, retries,
  backpressure, target rate limits, and reassignment.
- Build a collector SDK that emits normalized Entity, Relationship,
  Observation, and Event envelopes.
- Implement an HTTP/API reference collector.
- Implement SNMP Exporter as a built-in collector pack.
- Add Prometheus-compatible metric ingestion and query boundaries.
- Add windows_exporter for continuous metrics and a PSRP/CIM adapter for
  governed, on-demand diagnostics.
- Add collector coverage, health, lag, and version reporting.
- Add systemd service units and configuration layout for control-plane,
  collector, and execution-worker processes.
- Move Compose documentation under an explicit local development profile.

### Exit criteria

- Two collector workers can safely share and reassign target ownership.
- A new REST API collector can be defined without changing the core entity
  schema or writing directly to database tables.
- SNMP, controller API, and Windows observations use the same normalized
  ingestion envelope.
- A repeatable load test exercises at least 1,000 simulated targets and reports
  achieved intervals, queue lag, CPU, memory, timeouts, and time-series
  cardinality.
- Collector failure does not lose ownership state or create an uncontrolled
  retry storm.
- The production reference deployment runs without Docker.

## M2 — AI operator kernel

Status: **In progress**, while M1 production gates remain open

Foundation completed:

- Added persistent, provider-neutral AI provider, model, and purpose-routing
  contracts with a versioned database migration.
- Added OpenAI-compatible endpoint registration, outbound host allowlisting,
  bearer and X-API-key authentication modes, bounded `/models` connection tests,
  persisted health state, and audit events.
- Added environment-backed token secret references. Raw provider tokens are
  rejected by the AI settings API and are never returned to the browser.
- Added model capability metadata and route budgets for maximum iterations,
  tool calls, wall-clock time, and tokens.
- Added the dedicated `/settings/ai` page instead of placing provider and model
  configuration on the operations home page.
- Added persistent Investigation, immutable product checkpoint, evidence
  reference, typed Tool Registry, and audited tool-call tables and APIs through
  migration `f31a6c9d2e54`.
- Added strict InvestigationState and hypothesis contracts, immutable objective
  and scope, monotonic iteration/token accounting, wall-clock and tool budgets,
  duplicate-call prevention, secret-shape rejection, JSON Schema validation,
  bounded results, and deterministic escalation.
- Added the LangGraph reason → tools → evidence → reason kernel. It supports an
  official checkpoint saver, uses investigation IDs as thread IDs, and has
  PostgreSQL saver setup with strict MessagePack configuration.
- Added product checkpoint mirroring so each meaningful graph node updates the
  immutable iCheck investigation trace while LangGraph retains execution state.
- Added built-in, typed, database-backed `inventory.get_device` and
  `alerts.list_open` read-only tools. Core tools run in process; MCP remains an
  extension boundary and currently fails closed.
- Added `inventory.get_endpoint_history` with exact ID/MAC/IP selection,
  ambiguity rejection, active-first bounded IP/wired/Wi-Fi controller history,
  and data minimization that omits endpoint usernames and raw vendor payloads.
- Added the diagnose-risk `metrics.query_instant` tool over the existing
  allowlisted Prometheus-compatible boundary. PromQL length, timeouts, series
  count, response bytes, schemas, evidence, and audit are bounded; audit stores
  the query hash rather than the expression.
- Added a real OpenAI-compatible `/chat/completions` reasoner using the governed
  provider/model/credential settings, bounded request/response sizes, structured
  decision validation, gateway token usage, a deadline-aware timeout, and
  redacted success/failure audit.
- Added ordered fallback-model selection in AI settings and immutable candidate
  snapshots on investigations. The reasoner skips disabled candidates and
  retries retryable provider, transport, response, and structured-decision
  failures within the original wall-clock deadline. Every attempt is audited;
  failed candidates' reported tokens accumulate with the successful candidate
  and still enforce the investigation token budget.
- Verified an end-to-end two-iteration loop over a controlled model gateway:
  plan, device tool call, evidence persistence, reevaluation, conclusion,
  confidence, uncertainty, LangGraph checkpoint, and product checkpoint.
- Added persistent agent workers and one durable execution per investigation,
  bootstrap enrollment with rotating bearer tokens, provider capability matching,
  atomic leases, renewal, expiry takeover, attempt counters, and cooperative
  cancellation.
- Added ordered execution events, cursor-based JSON reads, resumable SSE using
  `Last-Event-ID`, graph-node progress, and bounded terminal/timeout behavior.
- Added a standalone PostgreSQL-only agent worker with per-node ownership checks,
  lease renewal, cancellation observation, fresh-run versus checkpoint-resume
  dispatch, terminal acknowledgement, crash-gap reconciliation, and a hardened
  systemd unit.
- Verified graph interruption, graph reconstruction with the same thread ID,
  continuation without replaying the completed tool, worker execution, stale
  lease reassignment, cancellation, and terminal-commit crash reconciliation.
- Replaced the conventional monitoring dashboard with the initial AI L1
  operator workspace. An operator can submit an outcome, create and start a
  durable investigation, follow resumable SSE execution progress, cancel an
  active execution, and inspect its conclusion, confidence, uncertainty,
  evidence ledger, tool activity, prioritized alerts, agent capacity, and real
  collector gaps. The home page contains no synthetic fallback inventory;
  endpoint and device details remain under Assets.
- Documented the implemented information architecture, endpoint dependencies,
  failure states, and remaining authorization/approval gates in
  `docs/operator-workspace.md`. The slice passes frontend lint and a Node 22
  production build.
- Added immutable principal, permission, and authorization-scope snapshots to
  investigations. Model tool projection, tool-call persistence, and database
  execution independently enforce each tool's required permissions.
- Added durable, exact-plan action proposals and four-eyes decisions. LangGraph
  pauses before a change, the requester cannot self-approve, stale hashes fail,
  and a decision resumes the same checkpointed thread. Ambiguous `executing`
  actions are never automatically replayed after worker loss.
- Added the dedicated `/approvals` review page with full arguments, plan hash,
  requester, reasoned approve/reject controls, and audit-backed status.

Current boundary:

- The PostgreSQL saver adapter is wired, but live PostgreSQL restart/resume
  acceptance has not run. In-memory tests prove graph rebuild/resume semantics;
  they do not prove a process crash against the production database.
- Per-target scope enforcement, MCP execution, topology/range-metric/log/Windows
  tools, deeper situation drill-down, and production change adapters with
  post-check/rollback remain open. Fallback is covered by controlled gateways
  but still requires live provider compatibility acceptance.
- The integration gateway is simulated in tests; no external model endpoint is
  contacted by the automated suite.

### Scope

- Add AI provider, base URL, authentication type, model, capability, and routing
  configuration pages and APIs.
- Store only secret references and provide redacted provider connection tests.
- Introduce LangGraph with durable PostgreSQL checkpoints.
- Define `InvestigationState`, evidence references, hypotheses, budgets,
  approval state, conclusions, and escalation reasons.
- Build a typed Tool Registry, policy gate, credential broker interface, and
  complete tool-call audit.
- Implement a bounded plan → tool → evidence → evaluate loop.
- Add read-only tools for entities, endpoint history, alerts, topology,
  Prometheus queries, SNMP-derived state, Windows diagnostics, and logs.
- Implement iteration, time, token, and tool-cost limits, duplicate-call
  prevention, target rate limits, and L2 escalation.
- Replace the conventional home dashboard with an AI L1 workspace.

### Exit criteria

- A user can configure and test a model without editing environment files.
- The model never sees provider or infrastructure credentials.
- An investigation survives a worker restart and resumes from its checkpoint.
- Every answer links to persisted evidence and reports confidence and
  uncertainty.
- A read-only investigation stops or escalates predictably when budgets are
  exhausted.
- The home page contains AI summary, prioritized situations, active
  investigations, approvals, and collection gaps; terminal inventory is a
  dedicated subpage.

## M3 — In-product Capability Studio

Status: **Planned**, depends on M1 artifact contracts and M2 agent kernel

### Scope

- Add a conversational artifact authoring workspace.
- Implement Collector Designer from API descriptions, samples, MIBs, command
  output, and natural-language requirements.
- Implement Tool and Skill Designer with input/output schemas, permissions,
  dependencies, tests, and documentation.
- Implement a workflow template editor supporting fixed branches, agent-loop
  nodes, triggers, budgets, approvals, post-checks, and rollback.
- Implement AI-generated topology/view definitions and preview data.
- Add deterministic schema, dependency, security, policy, secret-leak, and
  compatibility validation.
- Add isolated sandbox execution, fixtures, historical replay, semantic diffs,
  canary rollout, runtime health, export/import, and rollback.
- Add an MCP gateway for focused external and user capability packs.

### Exit criteria

- A user creates and publishes a working REST collector entirely within iCheck.
- A user creates a topology view and an investigation workflow through
  conversation and can refine both after previewing the result.
- Published versions are immutable and deployments can roll back to a selected
  healthy version.
- Generated artifacts are exportable and do not depend on hidden conversation
  context.
- Failed runtime executions can be opened directly as an AI-assisted artifact
  revision.

## M4 — Situation, incident, and topology intelligence

Status: **Planned**, depends on M2 and M3

### Scope

- Correlate alerts and observations into Situations.
- Add service-impact, dependency, and topology-path reasoning.
- Add incident lifecycle, timelines, evidence graphs, and root-cause records.
- Generate contextual visualizations from an investigation and allow useful
  views to be saved as versioned artifacts.
- Add dedicated assets, endpoints, topology, incidents, and raw telemetry
  subpages.
- Integrate external ticketing and collaboration systems through capability
  adapters.

### Exit criteria

- The AI groups related symptoms without hiding the underlying alert evidence.
- An operator can move from Situation to evidence, topology, endpoint history,
  and investigation trace without using protocol-specific navigation.
- Generated views are reproducible from their stored specification.

## M5 — Governed action

Status: **Planned**, depends on reliable evidence and artifact governance

### Scope

- Add Ansible Runner and replaceable execution backends.
- Add change requests, plans, diffs, pre-checks, post-checks, rollback, and
  maintenance windows.
- Add RBAC, credential scopes, peer review, four-eyes approval, and risk policy.
- Use durable human interrupts for every policy-controlled agent action.
- Extend audit across conversations, model decisions, artifacts, tools, changes,
  approval, execution, and verification.

### Exit criteria

- No state-changing tool can bypass policy or obtain raw credentials.
- Requesters cannot approve their own protected changes.
- Interrupted agent workflows resume the same versioned state after approval.
- Every executed change has a verification result and an available rollback
  outcome.

## M6 — Scale and capability ecosystem

Status: **Later**

- Multi-tenant and regional control-plane isolation.
- Collector and agent-worker autoscaling policies.
- Signed capability packs, organization catalogs, dependency resolution, and
  compatibility gates.
- Additional network, server, virtualization, storage, cloud, database, and
  application packs.
- Upgrade, disaster recovery, capacity, security, and long-duration reliability
  test programs.

## M7 — Governed autonomous operations

Status: **Later**

- Pre-approved remediation for low-risk, well-understood conditions.
- Automated validation and rollback.
- Policy-bounded closed-loop operations.
- Continuous artifact-quality evaluation based on runtime evidence.

High-risk changes continue to require human approval. Autonomy is earned per
capability and policy, not enabled by a global switch.

## Immediate implementation backlog

The local non-container Prometheus/SNMP installation, device onboarding, and
automatic preflight slices were completed and verified on 2026-09-18. The
immediate backlog continues M1 while preparing M2 interfaces:

1. When the lab is ready, enroll representative SNMP devices through the web
   UI, run positive and denied-target tests, measure series cardinality, and
   validate a scalable remote-write backend.
2. Install and validate windows_exporter on a representative Windows host.
3. Add mTLS, control-plane RBAC, and an external credential-provider adapter;
   connect the PSRP/CIM executor only after that boundary passes review.
4. Add generated-code sandbox and fixture execution.
5. Run multi-worker failure and 1,000-target load tests with cardinality reports.
6. Complete the `AgentProfile`, privacy/cost policy, and external Vault/KMS
   credential-provider contracts; provider, model, routing, and environment
   secret-reference schemas are implemented.
7. Run PostgreSQL process-kill/resume and multi-worker lease-race acceptance for
   the implemented agent worker, validate fallback against live providers, then
   add permission policy.
8. Exercise the implemented AI L1 workspace against the lab and a live model
   route, then add authenticated identities, permission-aware tool visibility,
   durable approval interactions, and deeper situation drill-down.

## Definition of done for every capability

A capability is not done when generated code merely runs once. It is done when:

- Its typed contract and normalized outputs are documented.
- Automated validation and tests pass.
- Secrets remain brokered and redacted.
- Permissions and operational risk are explicit.
- Runtime health, latency, errors, and audit are observable.
- A version can be promoted, deprecated, exported, and rolled back.
- Agent-facing descriptions state when to use it and when not to use it.
- Failure behavior and escalation are deterministic.
