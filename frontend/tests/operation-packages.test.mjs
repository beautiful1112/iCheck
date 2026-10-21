import assert from "node:assert/strict";
import test from "node:test";
import {readFileSync} from "node:fs";

test("package UX separates import, dependencies and execution", () => {
  const page = readFileSync(new URL("../app/studio/packages/page.tsx", import.meta.url), "utf8");
  for (const text of ["Check readiness", "Approve and import", "Install / manage MCP server",
    "Recheck dependencies and validate drafts", "Download portable package", "Advanced signed packs"]) assert.ok(page.includes(text));
  assert.match(page, /file.size > 2_000_000/);
  assert.match(page, /serial !== epoch.current/);
  assert.match(page, /icheck:namespace-changed/);
  assert.doesNotMatch(page, /localStorage\.setItem|sessionStorage\.setItem/);
  assert.doesNotMatch(page, /extensions\/install|schedule-activation/);
});

test("provider configuration offers native Orion credentials and bridge separately", () => {
  const page = readFileSync(new URL("../components/monitoring-integrations.tsx", import.meta.url), "utf8");
  assert.match(page, /solarwinds_orion/); assert.match(page, /rest_webhook/);
  assert.match(page, /SWIS password/); assert.match(page, /Read-only API token/);
  assert.match(page, /setPassword\(""\)/);
  assert.doesNotMatch(page, /planned, not available yet/);
});
