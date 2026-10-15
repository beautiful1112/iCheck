import test from "node:test";
import assert from "node:assert/strict";
import { oauthObservationSummary } from "../lib/mcp-oauth-observation.ts";

const now = Date.parse("2030-01-01T00:00:00Z");
const receipt = { generation: "a".repeat(32), vault_version: 3,
  token_expires_at: "2030-01-01T00:05:00Z", observed_at: "2030-01-01T00:00:00Z",
  received_at: "2030-01-01T00:00:00Z", coordination_state: "ready", source: "agent" };
const server = { oauth_status: "connected", oauth_generation: receipt.generation,
  oauth_bundle_version: 1, oauth_credential_observation: receipt };

test("a refreshed worker expiry is labeled observed, never an execution grant", () => {
  const value = oauthObservationSummary(server, now);
  assert.equal(value.state, "ready");
  assert.equal(value.expiry, receipt.token_expires_at);
  assert.match(value.detail, /Agent worker.*Vault v3.*not an execution grant/);
});
test("missing, revoked and replaced consent cannot present a current observation", () => {
  for (const value of [{ ...server, oauth_credential_observation: null },
    { ...server, oauth_generation: null }, { ...server, oauth_generation: "b".repeat(32) },
    { ...server, oauth_status: "revoked" }, { ...server, oauth_status: "revocation_pending" }]) {
    assert.equal(oauthObservationSummary(value, now).state, "unavailable");
  }
});
test("an old receipt remains explicitly stale even when its token lifetime is longer", () => {
  assert.equal(oauthObservationSummary(server, now + 300_000).state, "stale");
  assert.equal(oauthObservationSummary(server, now + 299_999).state, "ready");
});
test("uncertain, refreshing and revoking observations cannot masquerade as ready", () => {
  for (const coordination_state of ["uncertain", "refreshing", "revoking"]) {
    assert.equal(oauthObservationSummary({ ...server, oauth_credential_observation: { ...receipt, coordination_state } }, now).state, coordination_state);
  }
  assert.equal(oauthObservationSummary({ ...server, oauth_credential_observation: { ...receipt, token_expires_at: new Date(now).toISOString() } }, now).state, "expired");
});
test("invalid clocks, lower Vault versions and malformed observation metadata fail closed", () => {
  for (const next of [{ vault_version: 0 }, { vault_version: 1.5 }, { observed_at: "invalid" },
    { token_expires_at: "invalid" }, { received_at: "invalid" }, { source: "unknown" },
    { observed_at: new Date(now + 30_001).toISOString() }, { coordination_state: "connected" }]) {
    assert.equal(oauthObservationSummary({ ...server, oauth_credential_observation: { ...receipt, ...next } }, now).state, "uncertain");
  }
  assert.equal(oauthObservationSummary({ ...server, oauth_bundle_version: 4 }, now).state, "uncertain");
  assert.equal(oauthObservationSummary(server, NaN).state, "uncertain");
});
