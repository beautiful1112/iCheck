import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
const read = name => readFileSync(new URL(name, import.meta.url), "utf8");
test("provider timeout is explicit, bounded, stale-protected and does not send secrets", () => {
  const source = read("../components/ai-provider-timeout-control.tsx");
  for (const term of ["expected_request_timeout_seconds", "expected_connection_revision", "runtime-settings", "min={1}", "max={120}", "no AI call was made", "icheck:namespace-changed", "SESSION_CHANGE_KEY"]) assert.ok(source.includes(term));
  assert.doesNotMatch(source, /api_key|\/probe|\/check|localStorage\.setItem|sessionStorage/);
  const guided = read("../components/provider-setup.tsx");
  assert.match(guided, /connectionRevision=\{connection\.revision\}/);
  assert.match(guided, /useState\("120"\)/);
  assert.match(read("../app/settings/ai/page.tsx"), /request_timeout_seconds: Number\(providerTimeout\)/);
});
