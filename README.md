# iCheck

**iCheck — AI-Native Infrastructure Operations**

> Observe. Understand. Act.

iCheck is an AI-native, self-extensible IT operations agent platform. The AI
acts as an infrastructure engineer. The GUI provides visualization, evidence,
operational awareness, governance, and human authorization.

It is **not** a traditional NMS with a chatbot attached. It is also not a
monitoring catalog whose capabilities only grow through vendor releases. The
intended product is an agent runtime plus an in-product Capability Studio:
users describe an operational purpose, iCheck investigates or designs the
missing capability, and deterministic platform controls validate, test,
approve, publish, and roll it back.

```text
AI decides WHAT it needs.
The capability platform decides HOW to do it.
Humans decide WHETHER risky changes are allowed.
```

The full product definition, architectural rules, and long-term phases live in
[`iCheck_project_design.md`](./iCheck_project_design.md). Milestone status and
exit criteria live in [`docs/development-plan.md`](./docs/development-plan.md).
This README describes **this repository**, which is an early executable slice
of that design, not the finished product.

## Product loops

The first AI-native MVP in the design must prove three loops, focused on
Network, Linux, and Windows:

```text
Observe      a collector produces normalized evidence
Investigate  a durable, bounded agent uses typed tools and cites evidence
Extend       a user creates, tests, publishes, and revises a capability
             inside iCheck, without a separate IDE
```

| Loop | In this repository | Still open |
|---|---|---|
| Observe | Identity, alerts, versioned collector packs, workers, device onboarding and activation | Envelope-to-knowledge mapping, live SNMP/Windows lab acceptance, scale |
| Investigate | Bounded LangGraph kernel, four read-only tools, AI L1 home | Live-provider acceptance, topology/log/Windows tools, situation intelligence |
| Extend | Artifact registry for **built-in** collector packs | In-product Capability Studio (M3). Users cannot yet author collectors through conversation |

## Current status

Status names match the [development plan](./docs/development-plan.md).

| Milestone | Status | Meaning here |
|---|---|---|
| M0 Identity, alerts, ingest | Complete | MAC/IP/Wi-Fi history and stateful alerts |
| M1 Collection and data foundation | In progress | Control plane, packs, and onboarding exist; production gates remain |
| M2 AI operator kernel | In progress | Working kernel and first L1 surface; not a complete operator |
| M3 Capability Studio | Planned | Conversational artifact authoring is out of this slice |
| M4 Situations and incidents | Planned | Home shows alerts; it does not yet correlate them into situations |
| M5–M7 Governed action, scale, autonomy | Planned / later | Four-eyes **kernel** exists; production change adapters do not |

## What this slice implements

### Knowledge and alerts

PostgreSQL-ready inventory with MAC-normalized endpoints, historical IP
assignments, wired attachments, and Wi-Fi controller sessions. Mutable facts
are observations with first/last-seen state, not overwritten CMDB fields.
Alert rules cover weak RSSI, IP change, and new endpoints, with
deduplication, acknowledgement, recovery, and resolution.

Collectors can still post the original M0 contracts:

```text
POST /api/v1/inventory/network-observations
POST /api/v1/inventory/wireless-snapshots
POST /api/v1/alerts/events
```

Those APIs remain the path into endpoint identity and alert state. Payloads
are in [`docs/collector-contracts.md`](./docs/collector-contracts.md).

### Collection control plane

Collectors are versioned artifacts with immutable published versions, not
hard-coded protocol modules. SNMP Exporter, windows_exporter, GET-only HTTP
JSON, and on-demand PSRP/CIM are built-in packs on that contract. Workers
enroll with a bootstrap token, heartbeat, claim leases, and emit Entity /
Relationship / Observation / Event **staging envelopes**.

The envelope table is the collector staging boundary. It is **not** yet
projected into the endpoint/alert model, and production time series belong in
Prometheus, not PostgreSQL. Metrics in this slice are a bounded
Prometheus-compatible query/health registry plus query-hash audit.

Operators register devices on `/assets/devices`, declare protocol intents, and
bind external credential **references** (never raw secrets). Site workers
preflight those intents. A published activation policy can then be previewed
and approved into a collector deployment. A device becomes `active` only after
fresh successful scheduled collection; failed, stale, or drifted deployments
are visible degraded states. See
[`docs/device-onboarding.md`](./docs/device-onboarding.md) and
[`docs/device-activation.md`](./docs/device-activation.md).

### Agent runtime

The kernel is a bounded LangGraph loop: reason → typed tools → persisted
evidence → reason again. Investigations snapshot route budgets, model
fallback, and the caller's permissions. Tool output is schema-checked and
stored as evidence; credentials, connection configuration, endpoint usernames,
and raw PromQL are excluded from evidence summaries and audit.

Built-in tools today:

- `inventory.get_device`
- `inventory.get_endpoint_history`
- `alerts.list_open`
- `metrics.query_instant`

A standalone `icheck-agent-worker` claims leased executions, checkpoints
progress, and emits ordered events (including resumable SSE). A state-changing
tool cannot run directly: it creates an exact-plan proposal, interrupts the
same LangGraph thread, and waits for a different principal to approve or
reject it. There is no Ansible/Nornir/Netmiko execution backend behind that
interrupt yet.

See [`docs/agent-runtime.md`](./docs/agent-runtime.md).

### Operator surfaces

The default route is an AI L1 workspace, not an inventory dashboard: submit an
objective, follow a durable investigation, inspect evidence and tool activity,
and see alerts, approvals, and collection gaps that need a human. Device and
terminal detail stay on `/assets/devices`. Provider and model configuration
stay on `/settings/ai`. Approvals stay on `/approvals`.

```text
AI decides WHAT it needs          →  /
The platform decides HOW          →  artifacts, workers, tools
Humans decide WHETHER             →  /approvals
Assets remain evidence            →  /assets/devices
Providers stay administration     →  /settings/ai
```

See [`docs/operator-workspace.md`](./docs/operator-workspace.md).

### Trust foundations

Credential profiles store only secret references. Models never receive
infrastructure passwords. Control-plane principals, roles, and revocable
token hashes exist; production refuses to start with authentication disabled.
The Compose demo still runs with authentication **disabled** unless you change
that. Browser OIDC/session login and per-target scope on every older route are
not done. See [`docs/control-plane-auth.md`](./docs/control-plane-auth.md)
and [`docs/ai-provider-configuration.md`](./docs/ai-provider-configuration.md).

## What this slice does not implement

Do not read the vision sections of the design as a description of the running
code.

- Capability Studio: no conversational collector, tool, skill, or workflow
  authoring.
- Generic CMDB graph: no first-class Entity / Relationship tables driving the
  operator UI.
- Situation / incident correlation, topology reasoning, or saved generated
  views.
- MCP gateways, sandbox execution of generated code, or user-published
  adapters beyond the four built-in collector packs.
- Production change engines (Ansible, Nornir, Netmiko) or closed-loop
  remediation.
- Live lab acceptance: real SNMP device scrape, windows_exporter install,
  remote write, PSRP credential executor, live model-provider compatibility,
  and PostgreSQL process-crash resume of an agent worker.

PSRP/CIM is policy-complete and fails closed until an external
credential-provider-backed executor is connected.

## Repository map

```text
backend/icheck/            FastAPI control plane, workers, and domain services
backend/migrations/        Alembic database migrations
frontend/                  AI L1, approvals, assets, and AI settings UI
tests/                     API and runtime tests
deploy/                    systemd and Prometheus reference units
docs/                      contracts for the implemented slices
iCheck_project_design.md   Product design and architectural rules
```

## Run the local demo with Docker

Docker Compose is a **development convenience** (design Rule 18). It starts
PostgreSQL, the API, and the UI. It does **not** start a collector worker, an
agent worker, Prometheus, or SNMP Exporter, and it does not enable
control-plane authentication.

```bash
docker compose up --build
```

Then open:

- AI operator: `http://localhost:5173`
- Approvals: `http://localhost:5173/approvals`
- Device onboarding: `http://localhost:5173/assets/devices`
- AI settings: `http://localhost:5173/settings/ai`
- API docs: `http://localhost:8000/docs`
- Health: `http://localhost:8000/api/v1/health`

Investigations queue in the API. They execute only when an agent worker is
running against the same PostgreSQL database and a provider/model route is
configured. Device preflight and collection require a collector worker.

Production is independently deployable control-plane, collector, and agent
processes on VMs or bare metal under systemd. Containers remain optional.
Reference units are under `deploy/systemd/`.

## Run locally

Backend (Python 3.12+):

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/alembic upgrade head
.venv/bin/python -m icheck.seed
.venv/bin/uvicorn icheck.main:app --reload
```

Without `ICHECK_DATABASE_URL` the API uses `./icheck.db`. Agent workers require
PostgreSQL; they will not use SQLite as a graph checkpoint store. Copy
[`.env.example`](./.env.example) and set at least:

```text
postgresql+psycopg://icheck:icheck@localhost:5432/icheck
```

Optional workers, in additional terminals, after the API is up:

```bash
.venv/bin/icheck-collector --control-plane http://127.0.0.1:8000 --name collector-local-01 --site LOCAL
ICHECK_DATABASE_URL=postgresql+psycopg://icheck:icheck@localhost:5432/icheck \
  ICHECK_AGENT_WORKER_NAME=agent-worker-local-01 \
  .venv/bin/icheck-agent-worker
```

Frontend (Node.js 22.13+):

```bash
cd frontend
npm ci
NEXT_PUBLIC_ICHECK_API_URL=http://localhost:8000/api/v1 npm run dev
```

## Test and validate

```bash
.venv/bin/pytest
ICHECK_DATABASE_URL=sqlite+pysqlite:////tmp/icheck-test.db .venv/bin/alembic upgrade head
```

The automated agent tests use a controlled OpenAI-compatible gateway. They do
not contact an external model provider.

## Current boundary

This repository contains a working **kernel** and the first operator surface
on top of an identity, alert, and collector control plane. It is not yet the
AI-native product described in the design: Observe is not a closed
collection-to-knowledge loop, Investigate is not a complete L1 operator, and
Extend has not started.

Open production gates include mTLS, browser identity, route-complete RBAC
scope, an external credential-provider adapter, sandbox execution, real-device
SNMP and windows_exporter acceptance, remote-write validation, live PSRP
execution, live-provider fallback, PostgreSQL worker crash/resume, and
1,000-target collector load tests.

Further reading:

- [`iCheck_project_design.md`](./iCheck_project_design.md) — vision and rules
- [`docs/development-plan.md`](./docs/development-plan.md) — milestones
- [`docs/mvp-architecture.md`](./docs/mvp-architecture.md) — slice architecture
- [`docs/agent-runtime.md`](./docs/agent-runtime.md) — investigation kernel
- [`docs/operator-workspace.md`](./docs/operator-workspace.md) — home UI contract
- [`docs/collector-contracts.md`](./docs/collector-contracts.md) — ingest and packs
- [`docs/control-plane-auth.md`](./docs/control-plane-auth.md) — principals and tokens
