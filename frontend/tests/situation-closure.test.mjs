import assert from "node:assert/strict";
import { test } from "node:test";
import { closureDeadlineFresh, closureLeaseMetadata, closureVersionEnabled } from "../lib/situation-closure.ts";

test("lease view whitelists metadata and never spreads a transient secret", () => {
  const result = closureLeaseMetadata({ request_id: "request", attempt_id: "attempt", epoch: 1,
    state: "claimed", lease_expires_at: "2026-10-06T00:00:00Z", lease_token: "fixture-only-secret",
    token_hash: "fixture-only-hash", arbitrary_extra: "excluded" });
  assert.deepEqual(Object.keys(result).sort(), ["attempt_id", "epoch", "lease_expires_at", "request_id", "state"]);
  assert.equal(JSON.stringify(result).includes("secret"), false);
});
for (const [label, value, now, expected] of [
  ["future", "2026-10-06T00:00:01Z", Date.parse("2026-10-06T00:00:00Z"), true],
  ["exact expiry", "2026-10-06T00:00:00Z", Date.parse("2026-10-06T00:00:00Z"), false],
  ["expired", "2026-10-05T00:00:00Z", Date.parse("2026-10-06T00:00:00Z"), false],
  ["missing", null, 0, false], ["invalid", "not-a-deadline", 0, false],
  ["non-finite clock", "2026-10-06T00:00:00Z", NaN, false],
]) test(label, () => assert.equal(closureDeadlineFresh(value, now), expected));
for (const [label, version, enabled, expected] of [
  ["v1 independent of v2 gate", 1, false, true], ["explicit enabled v2", 2, true, true],
  ["disabled v2", 2, false, false], ["missing v2 gate", 2, undefined, false],
  ["missing version", undefined, true, false], ["string version", "2", true, false],
  ["future version", 3, true, false], ["boolean version", true, true, false],
]) test(label, () => assert.equal(closureVersionEnabled(version, enabled), expected));
