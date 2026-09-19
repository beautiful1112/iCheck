# AI L1 operator workspace

## Product role

The default iCheck route is an operator workspace, not a traditional monitoring
dashboard and not a general-purpose chatbot. Its primary object is a durable
`Investigation`; conversation is an authoring mechanism for the objective, not
the system of record.

The home screen answers five questions:

1. What outcome should the AI operator investigate next?
2. What is it investigating now, and is that execution making progress?
3. Which persisted evidence and tool calls support the current conclusion?
4. What uncertainty, approval, or collection gap requires a human?
5. Which alert situation should become the next investigation?

Raw endpoint lists, IP/MAC history, Wi-Fi sessions, device configuration, and
protocol detail remain in `/assets/devices` or future contextual drill-down
pages. AI provider and model configuration remains in `/settings/ai`.

## Implemented information architecture

```text
/
├── objective composer
│   └── create + start a durable investigation
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
    ├── recent durable investigations
    ├── collector workers, queue, and recent failures
    └── prioritized alerts that can seed a new objective

/assets/devices   device onboarding, activation, runtime health, terminals
/settings/ai      providers, models, secret references, routing budgets
```

Topology and workflow entries are visible as planned destinations, but they do
not pretend to be implemented routes.

## API contract

The workspace consumes existing control-plane APIs; it has no UI-only execution
state:

| Purpose | API |
|---|---|
| Create an investigation | `POST /api/v1/agent/investigations` |
| Start and enqueue it | `POST /api/v1/agent/investigations/{id}/start` |
| Select recent work | `GET /api/v1/agent/investigations` |
| Read execution ownership/status | `GET /api/v1/agent/investigations/{id}/execution` |
| Read durable product trace | `GET .../{id}/checkpoints`, `/evidence`, `/tool-calls` |
| Read/reconnect execution trace | `GET /api/v1/agent/executions/{id}/events` and `/events/stream` |
| Stop active work | `POST /api/v1/agent/executions/{id}/cancel` |
| Prioritized situations | `GET /api/v1/dashboard/summary` |
| Collection gaps | `GET /api/v1/collectors/health` |
| Agent capacity | `GET /api/v1/agent/workers` |

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

- The browser submits an objective and actor label; provider credentials and
  infrastructure credential references never enter the page.
- The current tool projection remains read-only. A change-risk tool fails closed
  in the runtime.
- Cancellation is cooperative for running work and immediate for queued work;
  both paths are persisted and audited.
- Confidence and uncertainty are displayed separately. A conclusion without
  evidence does not become authoritative because it is rendered by the UI.
- Collector health is shown as counts and gaps; the UI does not invent a
  percentage coverage score.

## Verified and remaining

Verified for this slice:

- frontend lint under Node 22;
- production Vinext build of `/`, `/approvals`, `/assets/devices`, and
  `/settings/ai`;
- backend execution lifecycle, cursor event reads, SSE resume, cancellation,
  worker completion, and graph checkpoint/resume tests.

Still required before production acceptance:

- browser OIDC/session integration and RBAC on every legacy operator API;
- per-target authorization enforcement;
- live PostgreSQL worker process-kill/restart/resume acceptance;
- live-provider and real-lab end-to-end browser acceptance;
- situation, topology, and saved dynamic-view drill-down routes;
- accessibility and browser compatibility review with representative data
  volumes.
