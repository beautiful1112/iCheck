import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { unnamedSelects } from "../scripts/check-accessible-selects.mjs";

const component = readFileSync(new URL("../components/provider-setup.tsx", import.meta.url), "utf8");
const page = readFileSync(new URL("../app/settings/ai/page.tsx", import.meta.url), "utf8");

test("guided setup is primary while advanced reference forms are collapsed", () => {
  assert.ok(page.indexOf("<ProviderSetup") < page.indexOf("<details"));
  assert.match(page, /Advanced providers and external secret references/);
  assert.doesNotMatch(page, /Raw tokens never enter this page/);
  assert.match(page, /item.provider === "managed_ai"/);
});

test("provider presets drive the UI and changing provider clears secrets and approvals", () => {
  assert.match(component, /setup.presets.map/);
  assert.match(component, /preset: presetId/);
  assert.match(component, /\/ai\/managed\/connections/);
  assert.match(component, /setPresetId\(event.target.value\); setName\(event.target.value\); setApiKey\(""\); setApproved\(false\)/);
  assert.match(component, /connection\?\.base_url \?\? preset\?\.base_url/);
  assert.doesNotMatch(component, /const endpoint = "https:\/\/openrouter/);
  assert.match(page, /guided setup already creates these records/);
  assert.match(page, /Anthropic Messages/);
  assert.match(page, /not a currency bill/);
});

test("managed key UI is write-only, transient, transport guarded and namespace reset", () => {
  assert.match(component, /type="password" autoComplete="off"/);
  assert.match(component, /setApiKey\(""\); \/\/ Write-only/);
  assert.match(component, /window.location.protocol === "https:"/);
  assert.match(component, /icheck:namespace-changed/);
  assert.match(component, /SESSION_CHANGE_KEY/);
  assert.match(component, /current !== epoch.current/);
  assert.doesNotMatch(component, /localStorage|sessionStorage|console\./);
  assert.doesNotMatch(component, /\.api_key|\.encrypted_secret/);
});

test("route replacement is opt-in, server revision checked and controls named", () => {
  assert.match(component, /useState\(false\)/);
  assert.match(component, /replace_existing_routes: replaceRoutes/);
  assert.match(component, /expected_connection_revision: check.connection_revision/);
  assert.match(component, /Disable outbound access/);
  assert.deepEqual(unnamedSelects(component, "openrouter-setup.tsx"), []);
});

test("retired provider is identified and restored directly with existing lifecycle approval", () => {
  assert.match(component, /provider_enabled: boolean/);
  assert.match(component, /const retired = connection\?\.provider_enabled === false/);
  assert.match(component, /Provider retired:/);
  assert.match(component, /aria-label="Retired AI provider"/);
  assert.match(component, /<AICatalogControls kind="providers"[^>]*enabled=\{false\} onChanged=\{restored\}/);
  assert.match(component, /Restoring this provider does not enable outbound access/);
  assert.match(component, /\(retired\)/);
  assert.match(component, /async function restored\(\)[\s\S]*?await reload\(\);[\s\S]*?await onChanged\(\)/);
});

test("retired provider cannot verify, approve egress, replace keys, probe or save routes", () => {
  for (const name of ["toggleAccess", "verify", "testInference", "configure", "saveKey"]) {
    const match = component.match(new RegExp(`function ${name}\\([^]*?(?=\\n  (?:async )?function|\\n  return \\()`));
    assert.ok(match, name);
    assert.match(match[0], /retired/);
  }
  assert.match(component, /disabled=\{busy \|\| retired \|\| !connection\?\.outbound_enabled/);
  assert.doesNotMatch(component, /method: "POST"[^]*?\/restore/);
});
