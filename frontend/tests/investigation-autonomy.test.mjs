import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import test from "node:test";

const read = path => readFileSync(new URL(path, import.meta.url), "utf8");

test("automatic investigation has a discoverable standalone settings page", () => {
  const settings = read("../app/settings/ai/autonomy/page.tsx");
  assert.match(read("../app/settings/ai/page.tsx"), /href="\/settings\/ai\/autonomy"/);
  assert.match(settings, /All managed resources in this workspace/);
  assert.match(settings, /Resources at selected sites/);
  assert.match(settings, /expected_revision: policy.revision/);
  assert.match(settings, /Saving an enabled policy authorizes AI model charges/);
  assert.match(settings, /does not authorize device changes/);
  assert.match(settings, /dispatcher_healthy/);
  assert.doesNotMatch(settings, /authorized.*device.*select|run_as_principal_id/i);
});

test("chat defaults to backend-enforced diagnosis without requiring a workflow", () => {
  const operator = read("../app/page.tsx");
  assert.match(operator, /execution_mode: outputIntent \? "standard" : "diagnose"/);
  assert.match(operator, /no workflow required/);
  assert.match(operator, /AI chooses relevant tools/);
  assert.match(operator, /<InvestigationAssistance key=\{detail.investigation.id\}/);
});

test("missing capability opens a saved Studio brief without auto-generating or installing", () => {
  const studio = read("../app/studio/builder/page.tsx");
  assert.match(studio, /params.get\("capability_request"\)/);
  assert.match(studio, /\/autonomy\/requests\/\$\{capabilityRequest\}/);
  assert.match(studio, /loadedHandoff.current = capabilityRequest/);
  assert.match(studio, /Return to the investigation and continue/);
  const fetch = studio.indexOf("const handoffRequest =");
  const stop = studio.indexOf('const requested = params.get("session")', fetch);
  assert.doesNotMatch(studio.slice(fetch, stop), /method: "POST"|\/start|\/install/);
});

test("continuation makes new charges and retained-history semantics explicit", () => {
  const component = read("../components/investigation-assistance.tsx");
  assert.match(component, /Starts a new bounded read-only run/);
  assert.match(component, /previous approvals are not reused/);
  assert.match(component, /Continue with AI/);
  assert.match(component, /Save approach as a Skill brief/);
  assert.match(component, /if \(!message.trim\(\) \|\| busy\) return/);
});
