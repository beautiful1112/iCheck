import assert from "node:assert/strict";
import test from "node:test";
import {readFileSync} from "node:fs";
import {externalAlertLabel, feedApproval} from "../lib/integration-alerts.ts";

test("acknowledgement, silence, recovery and unavailable evidence remain distinct", () => {
  const row = {available: true, source_state: "open", suppressed: false, acknowledged: false};
  assert.equal(externalAlertLabel(row), "Open");
  assert.equal(externalAlertLabel({...row, acknowledged: true}), "Open · acknowledged");
  assert.equal(externalAlertLabel({...row, suppressed: true}), "Suppressed at source");
  assert.equal(externalAlertLabel({...row, source_state: "resolved"}), "Resolved at source");
  assert.equal(externalAlertLabel({...row, available: false}), "Source status unavailable");
});
test("feed consent pins connection and feed revisions with bounded intervals", () => {
  assert.deepEqual(feedApproval({revision: 3}, 4, true, 60), {
    expected_revision: 4, expected_feed_revision: 3, confirm: true, enabled: true, interval_seconds: 60,
  });
  for (const value of [0, 59, 3601, NaN, 60.5]) assert.throws(() => feedApproval({revision: 1}, 2, true, value));
});
test("separate alert tab never starts AI or source reads on mount and clears stale session responses", () => {
  const component = readFileSync(new URL("../components/integration-alerts.tsx", import.meta.url), "utf8");
  const parent = readFileSync(new URL("../components/monitoring-integrations.tsx", import.meta.url), "utf8");
  assert.match(parent, /"alerts", "External alerts"/);
  assert.match(component, /serial !== epochRef.current/);
  assert.match(component, /request !== requests.current/);
  assert.match(component, /mounted.current/);
  assert.match(component, /Silence AI for this episode/);
  assert.match(component, /does not silence source notifications/);
  assert.match(component, /settings\/ai\/autonomy/);
  assert.doesNotMatch(component, /localStorage|sessionStorage|\/preview|\/executions/);
});
test("native alert deep links and closure do not confuse acknowledgement with stop", () => {
  const source = readFileSync(new URL("../app/alerts/page.tsx", import.meta.url), "utf8");
  assert.match(source, /alert_id=/);
  assert.match(source, /Close in iCheck and stop AI/);
  assert.match(source, /\/resolve/);
});
