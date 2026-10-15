import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
const form = readFileSync(new URL("../components/device-credentials.tsx", import.meta.url), "utf8");
const approval = readFileSync(new URL("../components/onboarding-approval.tsx", import.meta.url), "utf8");
test("all device credential families have secure transient input", () => {
  for (const kind of ["snmp_v2c", "windows_password", "https_token", "ssh_password", "ssh_key"]) assert.ok(form.includes(kind));
  assert.match(form, /type="password"/); assert.match(form, /clearSecrets\(\); \/\/ Never retain/);
  assert.match(form, /window.location.protocol === "https:"/); assert.match(form, /SESSION_CHANGE_KEY/);
  assert.match(form, /icheck:namespace-changed/); assert.doesNotMatch(form, /localStorage|sessionStorage|console\./);
  assert.match(form, /expected_revision/); assert.match(form, /\/revoke/);
});
test("AI proposals require explicit reason and exact plan approval", () => {
  assert.match(approval, /Approve enrollment/); assert.match(approval, /preview_hash: preview.preview_hash/);
  assert.match(approval, /expected_plan_hash: preview.plan\?\.plan_hash/);
  assert.match(approval, /!reason.trim\(\)/); assert.match(approval, /monitoring is not activated/);
});
