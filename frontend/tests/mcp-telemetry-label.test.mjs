import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

test("MCP call summary names its active-tool scope without rewriting history", () => {
  const source = readFileSync(new URL("../app/settings/mcp/page.tsx", import.meta.url), "utf8");
  assert.match(source, /label: "Active tool calls"/);
  assert.match(source, /"No calls on active tools"/);
  assert.match(source, /% succeeded on active tools/);
  assert.doesNotMatch(source, /label: "Runtime calls"|"No calls recorded"/);
  assert.match(source, /activation\.successful_calls/);
});
