# iCheck agent runtime contract

## Purpose

The M2 kernel is the first executable AI-operator path. It is deliberately
separate from the dashboard and from collector scheduling: the model reasons
over typed, persisted evidence and cannot read credentials or directly mutate
infrastructure.

```text
Investigation + route snapshot
            ↓
OpenAI-compatible structured reasoner
            ↓
LangGraph bounded decision node
       ├── complete / escalate
       └── typed tool requests
                    ↓
             policy and schema gate
                    ↓
              internal tool handler
                    ↓
       persisted call + evidence reference
                    ↓
              reason with evidence
```

## Durable state ownership

iCheck and LangGraph persist different contracts:

- LangGraph checkpoint storage owns executable thread state and restart
  continuity. The production helper accepts PostgreSQL only, enables strict
  MessagePack mode, calls saver setup, and uses the investigation ID as the
  thread ID.
- iCheck product tables own the stable API and audit contract: investigations,
  immutable sequential checkpoints with SHA-256 state hashes, evidence
  references, and tool calls with argument/result hashes.

The separation keeps the user-visible investigation trace independent of a
specific orchestration library. SQLite plus the in-memory LangGraph saver is
used only for automated development tests. Live PostgreSQL restart/resume is an
open acceptance gate.

## Execution workers and events

Starting an investigation atomically creates a queued execution and its first
ordered event. Agent workers enroll with a dedicated bootstrap token, receive a
rotating bearer token, advertise provider capabilities, and atomically claim a
bounded number of compatible executions. Only lease-token hashes are stored.

Each graph node verifies ownership, checks cancellation, renews the lease,
persists the product checkpoint, and emits a bounded progress event. An expired
lease can be claimed by another worker; the assignment explicitly states whether
the same LangGraph thread must resume. If the graph committed a terminal
investigation but the worker crashed before acknowledging completion, the next
scheduler pass reconciles the execution without replaying the graph. An expired
cancelled run is similarly closed instead of remaining stuck.

Clients can read ordered events after a sequence or connect to the SSE endpoint.
SSE accepts `Last-Event-ID`, emits persisted event names and IDs, sends
keepalives, terminates on a terminal/waiting state, and returns a reconnectable
cursor on timeout.

The AI L1 home consumes this contract directly. It creates and starts durable
investigations, reads checkpoints/evidence/tool calls, follows execution events,
and exposes cancellation. It does not infer progress from chat text and does not
show fabricated activity when the API is unavailable. Its information
architecture and current limits are documented in `operator-workspace.md`.

The standalone `icheck-agent-worker` command requires PostgreSQL so production
cannot silently fall back to process-local checkpoints. A systemd reference unit
and environment template are under `deploy/systemd/`.

## Investigation state and bounds

The persisted state includes objective and immutable scope, status, iteration,
plan, typed hypotheses, evidence and tool-call IDs, confidence, conclusion,
uncertainty, and escalation reason. The selected route is snapshotted into each
investigation as maximum iterations, tool calls, wall-clock seconds, and tokens.

The runtime enforces:

- monotonic iteration and token counters;
- a request timeout capped by the investigation's remaining wall-clock budget;
- tool-call and token budgets;
- duplicate tool-and-argument call hashes;
- tool input and output JSON Schemas;
- response byte limits and secret-shape rejection;
- immutable objective/scope and terminal state;
- controlled escalation for model, tool, schema, and budget failures.

Only gateway-reported `usage.total_tokens` is charged. A model cannot choose its
own usage value. Prompts and raw model responses are not written to audit events.

## Model adapter

The first adapter calls an allowlisted OpenAI-compatible
`/chat/completions` endpoint. It uses the model name and default parameters from
the selected model profile and resolves bearer or X-API-key credentials on the
server through the existing credential reference. Requests and responses are
bounded to 1 MB.

The model returns a JSON-schema-guided decision. Provider-side strict mode is
disabled because tool argument objects differ per registered tool; iCheck then
performs fail-closed Pydantic validation of the decision and JSON Schema
validation of each selected tool's arguments. Malformed responses are audited
without response content and durably escalate the investigation.

The selected primary and ordered fallback model IDs are snapshotted when the
investigation is created; later route edits cannot alter an in-flight execution.
The worker can claim the route even if its primary is later disabled. For each
reasoning iteration, the adapter attempts the snapshot in order and continues
only after a retryable configuration, provider, transport, response-envelope,
or graph-decision failure. Local request-size and investigation-deadline
failures are non-retryable.

Every candidate attempt records model, provider, candidate position, fallback
state, outcome, and bounded error metadata. Provider-reported token usage from
an invalid primary response is added to the successful fallback usage; if all
candidates fail, metered failed usage is still applied to the graph and can
exhaust its token budget. Raw model content and credentials are never audited.

## Tool policy

The registry supports `internal` and `mcp` transports and observe, diagnose, and
change risk. Every investigation snapshots the authenticated principal,
permissions, and authorization scope. The reasoner projects only enabled
internal handlers permitted by that snapshot; persistence and execution enforce
the same permissions again.

Implemented tools:

| Tool | Purpose | Evidence |
|---|---|---|
| `inventory.get_device` | Bounded device identity, onboarding, connection verification, activation, and runtime health | Device reference |
| `inventory.get_endpoint_history` | Bounded, active-first IP, wired attachment, and Wi-Fi controller history selected by endpoint ID, MAC, or unambiguous IP | Endpoint reference |
| `alerts.list_open` | Bounded open/acknowledged alerts with optional severity filter | Alert references |
| `metrics.query_instant` | Bounded instant PromQL against an allowlisted registered metric backend | Backend plus query-hash reference |

`inventory.get_device` excludes connection configuration and credential profile
references. Endpoint history excludes usernames and raw vendor payloads. The
PromQL tool caps the expression at 2,048 characters, timeout at 15 seconds, and
result limit at 100; metric audit and evidence store its SHA-256 hash rather than
the raw expression. All successful tool results are validated, hashed, and
persisted; audit records contain hashes and status, not the result body.

Core tools are not separate MCP servers. MCP is reserved for external or
user-installed capability packs and currently fails closed. An executable
state-changing internal tool creates a durable proposal containing the exact
tool, arguments, purpose, requester, and plan hash. LangGraph interrupts before
the handler runs. A different principal with `changes.approve` must decide the
exact plan; approval or rejection requeues the existing execution and resumes
the same LangGraph thread. An action already marked `executing` after worker
loss is treated as outcome-unknown and is not replayed automatically.

## Verified behavior

Automated tests cover:

- typed registry, checkpoint, evidence, and tool-call API lifecycles;
- secret-shaped schemas, state-changing calls, duplicates, and exhausted
  budgets;
- LangGraph planning, tool use, evidence return, reevaluation, completion,
  checkpoint lookup, and deterministic failure escalation;
- a two-iteration database-backed run through a controlled
  OpenAI-compatible gateway, the real `inventory.get_device` handler, product
  checkpoints, LangGraph checkpoints, model/tool audits, confidence, and
  uncertainty;
- malformed model output escalation without persisting the private response;
- PostgreSQL DSN normalization and rejection of SQLite as a production graph
  checkpoint store;
- authenticated worker claims, token redaction, lease renewal/takeover,
  cooperative and immediate cancellation, capability filtering, ordered events,
  cursor reads, and resumable SSE;
- standalone worker completion, per-node progress, graph interrupt/rebuild/resume
  without tool replay, and terminal graph-commit crash reconciliation.
- immutable permission snapshots, forged-actor rejection, catalog filtering,
  execution-time permission enforcement, exact-hash four-eyes approval,
  same-thread change resume, and ambiguous-action replay prevention.

## Remaining M2 work

- PostgreSQL crash/restart/resume and cancellation acceptance;
- browser OIDC/session integration and per-target scope enforcement across all
  operator APIs;
- live-provider compatibility and fallback behavior outside the controlled test
  gateways;
- range metrics, topology, controller-specific, log, and Windows diagnostic tools;
- MCP gateway policy and sandboxed user capability execution;
- production change adapters with idempotency keys, post-checks, and rollback.
