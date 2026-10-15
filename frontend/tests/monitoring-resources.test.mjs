import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import test from "node:test";

test("Monitoring renders resource cards with nested checks, not SSH connections", () => {
  const page=readFileSync(new URL("../app/monitoring/page.tsx",import.meta.url),"utf8");
  assert.match(page,/data.items.map\(resource/);
  assert.match(page,/resource.checks.map\(target/);
  assert.match(page,/managed resources/);
  assert.match(page,/Monitoring checks/);
  assert.doesNotMatch(page,/configured connections|organized by collection method|On-demand tools/);
  assert.match(page,/epoch.current === serial/);
  assert.match(page,/encodeURIComponent\(target.connection_id\)/);
});
