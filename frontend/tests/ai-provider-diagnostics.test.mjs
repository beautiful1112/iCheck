import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
const read = name => readFileSync(new URL(name, import.meta.url), "utf8");
const details = read("../components/ai-provider-diagnostic-details.tsx");
test("safe provider metadata exposes the rejected parameter and constraint, not raw payloads", () => {
  for (const label of ["Provider code", "Rejected parameter", "Validation constraint", "Error type", "Schema keyword"]) assert.ok(details.includes(label));
  assert.match(details, /Exact validation constraint unavailable/);
  assert.match(details, /No specific rejected value is assumed/);
  assert.doesNotMatch(details, /dangerouslySetInnerHTML|\.raw|\.message|localStorage|sessionStorage/);
});
test("guided inference and investigation root cause both render safe validation details", () => {
  assert.match(read("../components/provider-setup.tsx"), /probe\?\.diagnostic && <AIProviderDiagnosticDetails/);
  assert.match(read("../components/ai-runtime-diagnosis.tsx"), /<AIProviderDiagnosticDetails diagnostic=\{data.diagnostic\}/);
});
test("Agent validation retains safe paths/rules, timeout bounds and late model usage", () => {
  for (const label of ["Safe Agent validation details", "issue.path", "issue.rule", "diagnostic.finish_reason", "Elapsed-time limit"]) assert.ok(details.includes(label));
  const runtime = read("../components/ai-runtime-diagnosis.tsx");
  assert.match(runtime, /Provider-reported usage/);
  assert.match(runtime, /historical counters are unchanged/);
  assert.match(runtime, /unresolved_charges/);
  const settings = read("../app/settings/ai/page.tsx");
  assert.match(settings, /provider limits apply to each model attempt/);
  assert.match(settings, /Model attempt elapsed-time limit/);
  assert.match(settings, /Mandatory reasoning enabled at minimal effort/);
});
