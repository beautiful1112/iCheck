import assert from "node:assert/strict";
import test from "node:test";
import {readFileSync} from "node:fs";
import {advanceSync, resumable, syncLabel, scheduleLabel} from "../lib/monitoring-integrations.ts";

const connection = {enabled: true, revision: 2};
const run = {id: "run", connection_revision: 2, cursor: 0, total: 1000, observed: 0, status: "in_progress", can_resume: true};

test("resume is bound to current enabled revision", () => {
  assert.equal(resumable(run, connection), true);
  assert.equal(resumable(run, {...connection, revision: 3}), false);
  assert.equal(resumable(run, {...connection, enabled: false}), false);
  assert.equal(resumable(null, connection), false);
  assert.match(syncLabel({...run, status: "completed"}), /observed/);
  assert.doesNotMatch(syncLabel({...run, status: "completed"}), /healthy/i);
});

test("one action handles 1000 hosts in bounded batches", async () => {
  const cursors = [];
  const result = await advanceSync(run, async current => {
    cursors.push(current.cursor);
    const cursor = current.cursor + 250;
    return {...current, cursor, observed: cursor, status: cursor === 1000 ? "completed" : "in_progress", can_resume: cursor < 1000};
  }, () => false, () => {});
  assert.deepEqual(cursors, [0, 250, 500, 750]);
  assert.equal(result.status, "completed");
});

test("page limits, source failures and pause stop further requests", async () => {
  let calls = 0;
  await advanceSync({...run, total: 10000}, async current => {calls++; return {...current, cursor: current.cursor + 250};}, () => false, () => {});
  assert.equal(calls, 10);
  calls = 0;
  await advanceSync(run, async current => {calls++; return {...current, status: "failed"};}, () => false, () => {});
  assert.equal(calls, 1);
  await advanceSync(run, async () => {throw new Error("Must not call");}, () => true, () => {});
});

test("stale or substituted progress never triggers another step", async () => {
  for (const wrong of [{...run}, {...run, id: "other"}, {...run, connection_revision: 3}]) {
    await assert.rejects(advanceSync(run, async () => wrong, () => false, () => {}), /Unexpected sync progress/);
  }
});

test("setup, imports and history are separated; secrets are not persisted in the browser", () => {
  const source = readFileSync(new URL("../components/monitoring-integrations.tsx", import.meta.url), "utf8");
  assert.match(source, /Imported resources/); assert.match(source, /Sync history/);
  assert.match(source, /Preview resources/); assert.match(source, /Enable and sync resources/);
  assert.match(source, /seenRevision.current/); assert.match(source, /serial !== epoch.current/);
  assert.doesNotMatch(source, /localStorage\.setItem|sessionStorage\.setItem/);
  assert.match(source, /type="password"/); assert.match(source, /Pause automatic sync to run manually/);
});

test("automatic sync status distinguishes pauses, active leases, errors and overdue workers", () => {
  const now = Date.parse("2026-10-20T12:00:00Z");
  const schedule = {enabled: true, next_run_at: "2026-10-20T12:05:00Z", lease_expires_at: null};
  assert.equal(scheduleLabel({...schedule, enabled: false}, now), "Automatic sync is off");
  assert.equal(scheduleLabel({...schedule, lease_expires_at: "2026-10-20T12:00:30Z"}, now), "Processing a batch");
  assert.match(scheduleLabel({...schedule, last_error: "source_timeout"}, now), /Waiting to retry/);
  assert.match(scheduleLabel({...schedule, last_error: "source_timeout", next_run_at: "2026-10-20T11:50:00Z"}, now), /Overdue/);
  assert.match(scheduleLabel({...schedule, active_run_id: "run"}, now), /Scan in progress/);
});

test("schedule UI explains recurring consent and retention without source calls on mount", () => {
  const source = readFileSync(new URL("../components/integration-schedule.tsx", import.meta.url), "utf8");
  assert.match(source, /Enable automatic sync/);
  assert.match(source, /Pause automatic sync/);
  assert.match(source, /Enabling approves recurring reads/);
  assert.doesNotMatch(source, /apiFetch|useEffect|localStorage/);
  const parent = readFileSync(new URL("../components/monitoring-integrations.tsx", import.meta.url), "utf8");
  assert.match(parent, /expected_schedule_revision/);
  assert.match(parent, /GET status only/);
  assert.match(parent, /serial !== epoch.current/);
});
