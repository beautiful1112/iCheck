import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
const read = path => readFileSync(new URL(path, import.meta.url), "utf8");
const setup = read("../components/provider-setup.tsx");
const controls = read("../components/ai-catalog-controls.tsx");
const diagnosis = read("../components/ai-runtime-diagnosis.tsx");
const page = read("../app/settings/ai/page.tsx");
test("model generation test is explicit, paid, schema checked and bound to revision", () => {
  assert.match(setup, /Test model inference/); assert.match(setup, /may incur charges/);
  assert.match(setup, /!approveCharge/); assert.match(setup, /probe_reservation_id: probe.quota_reservation_id/);
  assert.match(setup, /expected_configuration_hash: check.configuration_hash/);
  assert.match(setup, /probe.model_id !== modelId/); assert.match(setup, /setProbe\(null\)/);
  assert.match(setup, /Batch-only variants are excluded/);
});
test("catalog removal previews exact dependencies and requires a reason, never cascades", () => {
  assert.match(controls, /lifecycle\/preview/); assert.match(controls, /preview_hash: plan.preview_hash/);
  assert.match(controls, /plan.blockers/); assert.match(controls, /!reason.trim\(\)/);
  for (const kind of ["credentials", "providers", "models", "routes"]) assert.ok(page.includes(`kind="${kind}"`));
  assert.match(page, /Retired AI configuration/); assert.match(page, /not simultaneous calls/);
  assert.match(page, /This form does not create environment variables or configure Vault/);
});
test("failure diagnosis is in-product, permission gated, with explicit new-task retry", () => {
  assert.match(diagnosis, /\/diagnosis/); assert.match(diagnosis, /Root cause and proposed repair/);
  assert.match(diagnosis, /canManage &&/); assert.match(diagnosis, /canRetry &&/);
  assert.match(diagnosis, /\/repair-retry/); assert.match(diagnosis, /device approval remains separate/);
});
test("all repair controls discard cross-namespace responses and do not store secrets", () => {
  for (const source of [setup, controls, diagnosis]) {
    assert.match(source, /epoch.current/); assert.match(source, /icheck:namespace-changed/);
    assert.match(source, /SESSION_CHANGE_KEY/); assert.doesNotMatch(source, /localStorage|sessionStorage|console\./);
  }
});
