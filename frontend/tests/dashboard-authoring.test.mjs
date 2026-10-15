import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import test from "node:test";
import {canAuthorDashboard, dashboardAuthoringRequest} from "../lib/dashboard-authoring.ts";

test("dashboard authoring requires read/create and workspace metric access, not write access", () => {
  assert.equal(canAuthorDashboard(null), false);
  const principal = {authorization_scope: {all: true}, permissions: ["investigations.create", "investigations.read", "metrics.read"]};
  assert.equal(canAuthorDashboard(principal), true);
  assert.equal(canAuthorDashboard({...principal, authorization_scope: {all: false}}), false);
  assert.equal(canAuthorDashboard({...principal, permissions: ["metrics.manage"]}), false);
});

test("new and revision runs use native scoped diagnosis and never request apply", () => {
  const created = dashboardAuthoringRequest("connection-id", "Show interface errors", null);
  assert.equal(created.execution_mode, "diagnose");
  assert.deepEqual(created.scope, {capability_task: "grafana-dashboard", grafana_connection_id: "connection-id", authoring_brief: "Show interface errors"});
  assert.match(created.objective, /Discover actual metrics/);
  assert.match(created.objective, /Do not apply changes/);
  const revised = dashboardAuthoringRequest("connection-id", "Add errors", {uid: "existing", title: "Network"});
  assert.match(revised.objective, /Revise existing dashboard UID existing/);
  assert.match(revised.objective, /resource version first/);
  assert.match(revised.objective, /preserve panels, variables and settings/);
  const refined = dashboardAuthoringRequest("connection-id", "Use the last 24 hours", null, "prior-change");
  assert.match(refined.objective, /Read previous proposal prior-change using grafana.changes.get/);
});

test("dashboard exposes direct AI authoring and keeps manual JSON behind advanced", () => {
  const page = readFileSync(new URL("../app/dashboards/page.tsx", import.meta.url), "utf8");
  assert.match(page, /<DashboardAiAuthoring/);
  assert.match(page, />Edit with AI</);
  assert.match(page, /Advanced: manual preview and JSON definition/);
  assert.match(page, /Confirm and apply/);
  const component = readFileSync(new URL("../components/dashboard-ai-authoring.tsx", import.meta.url), "utf8");
  assert.match(component, /Saved AI conversations/);
  assert.match(component, /Model charges may apply/);
  assert.match(component, /current !== epoch.current/);
  assert.match(component, /submitting.current/);
  assert.match(component, /capability_task=grafana-dashboard/);
  const effect = component.slice(component.indexOf("useEffect(() =>"), component.indexOf("function choose"));
  assert.doesNotMatch(effect, /method: "POST"|\/start/);
});

test("silence controls disclose AI stopping and no automatic restart", () => {
  const page = readFileSync(new URL("../app/alerts/alertmanager/page.tsx", import.meta.url), "utf8");
  assert.match(page, /also stops automatic AI investigation/);
  assert.match(page, /Ending a silence does not restart/);
  const operator = readFileSync(new URL("../app/page.tsx", import.meta.url), "utf8");
  assert.match(operator, /execution\?\.cancellation_reason/);
  assert.match(operator, /"execution.cancellation_requested", "execution.reconciled"\]\.includes\(next.event_type\)/);
});
