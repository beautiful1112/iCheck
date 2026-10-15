import test from "node:test";
import assert from "node:assert/strict";
import { mcpAttestationIsFresh } from "../lib/mcp-attestation.ts";

const value = { server_id: "server", artifact_version_id: "version", status: "passed", expires_at: "2030-01-01T00:00:00Z" };
const expiry = Date.parse(value.expires_at);

test("attestation is usable only for the exact passed server and immutable version", () => {
  assert.equal(mcpAttestationIsFresh(value, "server", "version", expiry - 1), true);
  for (const next of [undefined, { ...value, server_id: "other" }, { ...value, artifact_version_id: "other" },
    { ...value, status: "pending" }, { ...value, status: "consumed" }, { ...value, status: "failed" }]) {
    assert.equal(mcpAttestationIsFresh(next, "server", "version", expiry - 1), false);
  }
});

test("expiry boundary, invalid evidence and invalid wall clock fail closed", () => {
  for (const now of [expiry, expiry + 1, NaN, Infinity]) {
    assert.equal(mcpAttestationIsFresh(value, "server", "version", now), false);
  }
  for (const expires_at of [null, "invalid", "1970-01-01T00:00:00Z"]) {
    assert.equal(mcpAttestationIsFresh({ ...value, expires_at }, "server", "version", 0), false);
  }
  assert.equal(mcpAttestationIsFresh(value, "", "version", 0), false);
  assert.equal(mcpAttestationIsFresh(value, "server", "", 0), false);
});

test("submit-time validation catches expiry after an earlier valid render or recovery prompt", () => {
  assert.equal(mcpAttestationIsFresh(value, "server", "version", expiry - 5000), true);
  assert.equal(mcpAttestationIsFresh(value, "server", "version", expiry), false);
});
