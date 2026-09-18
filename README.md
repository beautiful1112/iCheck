# iCheck

iCheck is an AI-native, self-extensible IT operations agent platform. The AI
Agent Runtime is the product kernel rather than a chatbot added to a traditional
monitoring console. Users will be able to create and iterate collectors,
topology views, tools, skills, workflows, and visualizations through conversation
inside iCheck.

This repository is the first runnable vertical slice of the larger
[`product design`](./iCheck_project_design.md). The accepted implementation
sequence and exit criteria are in the
[`development plan`](./docs/development-plan.md).

The kickoff release focuses on two operational foundations:

- Stateful alerts with rules, deduplication, acknowledgement, and resolution.
- Durable endpoint identity and history across IP, MAC table, ARP/DHCP, and Wi-Fi
  controller observations.

## What is implemented

- FastAPI service with generated OpenAPI documentation.
- PostgreSQL-ready SQLAlchemy schema with an SQLite development default.
- Versioned Alembic migration.
- Device inventory for switches, routers, controllers, servers, and future types.
- MAC-normalized endpoint identities with first/last-seen timestamps.
- Historical IP assignments with source, collector, VLAN, and active state.
- Wired attachment history from MAC/ARP observations.
- Wi-Fi controller snapshots with AP, SSID, BSSID, band, channel, VLAN, RSSI, SNR,
  connect/disconnect state, and untouched vendor payload storage.
- Alert rules for weak wireless signal, endpoint IP changes, and new endpoints.
- Collector-facing manual alert event API.
- Operations dashboard with alert acknowledgement and endpoint search.
- Seed data and end-to-end API tests.
- Versioned Artifact and CollectorDefinition models with validate/publish
  lifecycle and content hashes.
- Collector deployments, worker registration, heartbeat, selectors, leases,
  run history, health summary, and idempotent normalized envelopes.
- Standalone GET-only HTTP JSON collector worker with an outbound host allowlist.
- systemd reference unit for VM/bare-metal collector deployment.
- Bootstrap-authenticated worker enrollment, per-worker token rotation, and
  worker-plus-lease authorization.
- Credential profiles with external secret references and adapter/worker scope.
- Bounded JSON Schema validation for generated collector contracts and
  deployment inputs.
- Durable artifact, credential, deployment, worker, and run audit events.
- Prometheus-compatible metric backend registry with bounded instant/range
  queries, health checks, remote-write metadata, and query-hash audit.
- Built-in SNMP Exporter collector artifact with Prometheus-text normalization
  and exporter/device network allowlists.
- Built-in windows_exporter pack for bounded metric previews plus Prometheus
  file-discovery and Windows service configuration examples.
- Deployment-scoped credential references, true on-demand collector execution,
  and a PSRP/CIM diagnostic pack limited to published read-only templates.
- systemd and Prometheus/SNMP Exporter templates for non-container deployments.
- Governed OpenAI-compatible provider registry with URL allowlisting,
  bearer/X-API-key secret references, redacted connection tests, and audit.
- AI model profiles and purpose-based routing budgets for iterations, tool calls,
  wall-clock time, and tokens.
- Dedicated `/settings/ai` administration page for credential references,
  providers, models, health checks, and bounded routes.

## Repository map

```text
backend/icheck/            FastAPI application and domain services
backend/migrations/        Alembic database migrations
frontend/                  React/Vinext operations dashboard
tests/                     End-to-end API tests
docs/                      MVP architecture and collector contracts
iCheck_project_design.md   Full product design and roadmap
```

## Run the local demo with Docker

The quickest complete setup requires Docker with Compose:

```bash
docker compose up --build
```

Then open:

- Dashboard: `http://localhost:5173`
- AI settings: `http://localhost:5173/settings/ai`
- API documentation: `http://localhost:8000/docs`
- Health check: `http://localhost:8000/api/v1/health`

The Docker stack creates the PostgreSQL schema, loads representative seed data,
and connects the dashboard to the API.

Docker Compose is not the production deployment architecture. Production will
support independently scalable control-plane, collector, and execution-worker
processes on VMs or bare metal under systemd. Containers remain optional.

## Run locally

Backend (Python 3.12+):

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/alembic upgrade head
.venv/bin/python -m icheck.seed
.venv/bin/uvicorn icheck.main:app --reload
```

Without `ICHECK_DATABASE_URL`, the backend uses `./icheck.db`. Set it to a
PostgreSQL URL for a shared environment:

```text
postgresql+psycopg://icheck:icheck@localhost:5432/icheck
```

Frontend (Node.js 22.13+), in a second terminal:

```bash
cd frontend
npm ci
NEXT_PUBLIC_ICHECK_API_URL=http://localhost:8000/api/v1 npm run dev
```

## Collector APIs

Network collectors post batches to:

```text
POST /api/v1/inventory/network-observations
```

Wi-Fi controller adapters post complete or partial client snapshots to:

```text
POST /api/v1/inventory/wireless-snapshots
```

With `complete_snapshot: true`, clients missing from the new controller snapshot
are marked disconnected. Their session history is retained.

Collectors and external monitoring systems can emit a condition to:

```text
POST /api/v1/alerts/events
```

The default low-RSSI rule automatically resolves its alert when a later client
snapshot reports a recovered signal. See
[`docs/collector-contracts.md`](./docs/collector-contracts.md) for payloads.

## Test and validate

```bash
.venv/bin/pytest
ICHECK_DATABASE_URL=sqlite+pysqlite:////tmp/icheck-test.db .venv/bin/alembic upgrade head
```

## Current boundary

This slice establishes the data and operations plane needed before adding AI
reasoning. Prometheus-compatible query boundaries, SNMP Exporter, and Windows
collector packs are implemented. A live non-container reference instance of
Prometheus 3.13.3 LTS and SNMP Exporter 0.30.1 is installed on host `zhao`, runs
under the dedicated `icheck` service account, starts through systemd, and binds
only to `127.0.0.1`. Configuration validation, local scrape health, PromQL, and
restart recovery have passed. No real SNMP device is enrolled yet, so device
scrape, timeout, and cardinality acceptance remain open. `windows_exporter` and
remote write are also not installed or configured.
The PSRP/CIM adapter is policy-complete but deliberately fails closed until an
external credential-provider-backed executor is connected. Controller vendor
APIs, LangGraph, Ansible, Nornir, and Netmiko are not yet connected.

AI provider, model, token-reference, connection-test, and routing-budget
configuration is now implemented as an M2 foundation. It does not yet provide a
LangGraph Agent Runtime, investigation checkpoints, a Tool Registry, MCP
servers, or in-product capability authoring. These are explicitly scheduled in
[`docs/development-plan.md`](./docs/development-plan.md); the configuration
foundation must not be represented as a functioning AI operator.

The collector control-plane API is an M1 foundation, not yet a production-ready
collector service. Application-layer worker authentication and the credential
broker contract are implemented. mTLS, user/RBAC authentication, an external
credential-provider adapter, sandbox execution, real-device SNMP acceptance,
remote-write validation, a live PSRP credential executor, and scale testing
remain open production gates.
