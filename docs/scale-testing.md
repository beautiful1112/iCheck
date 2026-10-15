# M1 scale and failure harness

The `icheck-scale-test` command exercises the real Collector scheduler,
envelope ingestion, durable knowledge-projection queue, and projection runtime.
It is an acceptance harness, not a synthetic database insert benchmark.

## Safety contract

The harness never falls back to `ICHECK_DATABASE_URL`. Supply a dedicated,
disposable database with `--database-url` or `ICHECK_SCALE_DATABASE_URL`, then
explicitly pass `--acknowledge-dedicated-database`. The database must:

- be PostgreSQL for representative evidence;
- be migrated to the checkout's sole current Alembic head, resolved once at
  run start rather than pinned to an obsolete revision;
- contain no Artifact, Device, CollectorDeployment, or KnowledgeProjection
  rows; and
- not be a development, demo, lab-inventory, or production database.

The command refuses a non-empty database. SQLite requires the additional
`--allow-sqlite-smoke` flag and always emits `"representative": false`.
SQLite output proves only that the harness path works; it is not M1 capacity
evidence.

For the 10-target SQLite smoke, the harness reserves one real claim per Worker
before starting its threads. A late-scheduled thread therefore still processes
its own assignment, and the report records
`sqlite_smoke_seeded_workers: true`. This small-sample scheduling aid does not
run on PostgreSQL: representative Worker distribution remains naturally
scheduled and must still meet the configured minimum share.

## Representative run

Create and migrate a new PostgreSQL database, then run:

```bash
ICHECK_SCALE_DATABASE_URL=postgresql+psycopg://USER:PASSWORD@HOST:5432/icheck_scale \
  .venv/bin/icheck-scale-test \
  --acknowledge-dedicated-database \
  --targets 1000 \
  --collector-workers 2 \
  --projection-workers 2 \
  --output /var/tmp/icheck-scale-report.json
```

The default run creates 1,000 independently scoped Devices and Deployments,
two Collector Workers, and two Projection Workers. Threads execute the same
claim, ingest, completion, and projection service functions used by deployed
workers.
Every scale-harness session is pinned to the seeded default tenant and region,
so PostgreSQL RLS and application namespace predicates remain active during
the run.

Before normal concurrent processing, the harness deliberately expires one
Collector lease and one Projection lease. It verifies reassignment and proves
that each stale owner is denied. This is deterministic lease-loss injection;
it does not by itself replace an operating-system process-kill and restart test.

The separate `icheck-projection-worker-recovery-test` command exercises the
actual Projection Worker process against one controlled network observation.
It accepts only an empty, migrated `icheck_projection_recovery_*` PostgreSQL
database through `ICHECK_PROJECTION_RECOVERY_DATABASE_URL`, requires
`--acknowledge-dedicated-database`, and rejects a database-owner or RLS-bypass
role. It locks the fixture endpoint row, waits for the first Worker to block
after claiming the projection, sends SIGKILL, waits for the 15-second lease to
expire naturally, and starts a second Worker. Run it only against a disposable
database, never against lab inventory or production data.

The separate `icheck-collector-worker-recovery-test` command uses a fresh,
migrated `icheck_collector_recovery_*` PostgreSQL database through
`ICHECK_COLLECTOR_RECOVERY_DATABASE_URL`, the same acknowledgement and role
restrictions, and a controlled loopback HTTP target. Two actual Collector
processes register with the real control plane; only that control plane and the
Projection Worker receive database access. After the first Collector is
SIGKILLed during an HTTP request, the second claims the naturally expired
15-second lease. The probe verifies that the old token cannot ingest or
complete its Run, then projects the replacement's single Envelope. It does
not test external device traffic, mTLS, or sustained load.

## Evidence and gates

The versioned `icheck.scale-report/v1` JSON records:

- configuration, database backend, schema head, and representative status;
- wall time, process CPU, maximum resident memory, and PostgreSQL database
  growth;
- completed target cycles, throughput, and achieved full-cycle time;
- collection start latency, collection duration, and projection lag at
  minimum, p50, p95, p99, and maximum;
- Worker distribution and minimum share;
- cancelled/reassigned Collector runs, projection retries, queue drainage,
  dead letters, timeouts, and hash-only Worker error fingerprints;
- projected endpoint count; and
- simulated time-series cardinality.

The cardinality value is the number of unique synthetic
`(target_index, metric_index)` label sets. No samples are remote-written by
this harness, so it does not prove Prometheus-compatible backend acceptance,
retention behavior, or real exporter cardinality controls.

A representative run passes only when all report gates pass, including exact
Collector and Projection success counts, one endpoint per target, drained
projection queue, no dead letters or Worker errors, observed lease
reassignment, use of every Worker above the configured minimum share, and
projection p95 within the configured bound.

## Current acceptance status

The harness and its SQLite-only automated smoke coverage are implemented. On
2026-09-25, an explicitly non-representative 1,000-target SQLite run at schema
head `1d5b9f7a4c82` completed 1,000 Collector and Projection cycles in 21.46
seconds, used both Workers in
each phase, observed both reassignments, produced 1,000 endpoints, reported no
timeout, dead letter, or Worker error, and measured 11.34-second projection p95
and 177.50 MiB process peak RSS. This validates the larger harness path, not
production capacity.

On 2026-10-03, a fresh, socket-only PostgreSQL 16.15 database on the
development host was migrated to `u3w5y7a9c1e4`. A non-owner, non-RLS-bypass
role ran the 1,000-target harness with RLS active. The saved
versioned report (private development evidence; not distributed)
passed all eleven gates: 1,000 Collector cycles, projections and endpoints;
both Worker pairs used; both lease reassignments observed; no dead letters,
timeouts or Worker errors. Wall time was 25.88 seconds, achieved throughput
38.64 target cycles/second, projection p95 13.43 seconds, process peak RSS
359.04 MiB, and database growth 9.60 MB. The 8,000-series cardinality figure
is simulated label-set counting, not remote-written samples. A second attempt
on the same non-empty database was refused before mutation. The generated
database and role were removed and the private server was stopped.

On 2026-10-03, the separate restricted-role, socket-only
Projection Worker process-loss report (private development evidence; not distributed)
passed all nine gates. Two actual Worker processes registered, the first was
killed while blocked on an endpoint row, the second reclaimed its naturally
expired lease and completed the projection on attempt two. Exactly one
endpoint and one IP observation remained, with no dead letter. This proves a
controlled Projection Worker process recovery, not Collector Worker recovery
or a capacity measurement.

The separate Collector Worker process-loss report (private development evidence; not distributed)
passed all thirteen gates on a fresh, restricted-role, socket-only PostgreSQL
database. The first actual process was killed while waiting for the controlled
HTTP target, and the second reclaimed the naturally expired lease. The first
Run was cancelled, both stale-token write attempts were rejected, and the
replacement Run produced one Envelope, one successful projection, one endpoint,
and one IP observation. A second attempt on the non-empty database was refused
before mutation. This is a single-target process recovery check, not a
representative Collector capacity or live-device test.

The scale report's `representative: true` means PostgreSQL rather than SQLite
in this v1 harness; it does **not** certify production-sized hardware,
external monitoring backends, or real devices. The 1,000-target run closes
the functional PostgreSQL code-path check, while separate single-envelope
probes close controlled Collector and Projection Worker crash/reclaim checks.
Production sizing, real SNMP/WLC/Windows, remote-write, sustained capacity,
production mTLS fault drills, and API/database restart remain lab gates.
