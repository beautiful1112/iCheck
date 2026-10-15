import assert from "node:assert/strict";
import { test } from "node:test";
import { formatAuthoringHeadroom } from "../lib/authoring-quota.ts";

const cases = [
  ["missing", null, "unavailable"],
  ["not loaded", undefined, "unavailable"],
  ["both unlimited", { actor_available: null, namespace_available: null }, "unbounded"],
  ["actor ceiling", { actor_available: 1000, namespace_available: 2000 }, "1,000"],
  ["namespace ceiling", { actor_available: 2000, namespace_available: 1000 }, "1,000"],
  ["namespace exhausted", { actor_available: null, namespace_available: 0 }, "0"],
  ["actor exhausted", { actor_available: 0, namespace_available: 1000 }, "0"],
  ["unlimited namespace", { actor_available: 42, namespace_available: null }, "42"],
  ["unlimited actor", { actor_available: null, namespace_available: 42 }, "42"],
  ["missing field", { actor_available: 42 }, "unavailable"],
  ["negative", { actor_available: -1, namespace_available: null }, "unavailable"],
  ["non-finite", { actor_available: NaN, namespace_available: 42 }, "unavailable"],
  ["fractional", { actor_available: 1.5, namespace_available: null }, "unavailable"],
  ["string", { actor_available: "42", namespace_available: null }, "unavailable"],
  ["unsafe integer", { actor_available: 9007199254740992, namespace_available: null }, "unavailable"],
];

for (const [name, quota, expected] of cases) {
  test(name, () => assert.equal(formatAuthoringHeadroom(quota, "en-US"), expected));
}
