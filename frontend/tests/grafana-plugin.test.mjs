import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {canManageGrafana, grafanaResourceLinks, proposalReference, readableDefinition} from "../lib/grafana-plugin.ts";

test("confirmation preview exposes native panel queries and variable definitions", () => {
  const preview = readableDefinition({panels: [{id: 1, title: "Scrape status", type: "timeseries", targets: [{expr: 'up{instance=~"$instance"}'}]}],
    templating: {list: [{name: "instance", type: "query", query: {query: "label_values(up, instance)"}}]}});
  assert.deepEqual(preview.panels[0], {title: "Scrape status", type: "timeseries", queries: ['up{instance=~"$instance"}']});
  assert.equal(preview.variables[0].query, "label_values(up, instance)");
});

test("display review distinguishes explicit off and time settings from omitted or invalid values", () => {
  const selected = readableDefinition({time:{from:"now-1h", to:"now"}, refresh:"", timezone:"utc", description:"Platform metrics only"});
  assert.equal(selected.timeRange, "now-1h → now");
  assert.equal(selected.refresh, "Off");
  assert.equal(selected.timezone, "utc");
  assert.equal(selected.description, "Platform metrics only");
  assert.equal(readableDefinition({refresh:"30s"}).refresh, "30s");
  const missing = readableDefinition({});
  assert.match(missing.timeRange, /Not specified/);
  assert.match(missing.refresh, /not an explicit off/);
  assert.match(readableDefinition({time:{from:"now-1h"}}).timeRange, /Invalid/);
  assert.match(readableDefinition({time:null, refresh:false}).refresh, /Invalid/);
  assert.match(readableDefinition({refresh:null}).refresh, /Invalid/);
});

test("proposal cards use a local reviewed ID, never an arbitrary model URL", () => {
  const id = "12345678-1234-1234-1234-123456789abc";
  const value = {id, resource_kind: "dashboard", status: "proposed", review_url: `/dashboards?change=${id}`, definition: {title: "Interfaces"}};
  assert.deepEqual(proposalReference(value), {id, title: "Interfaces", status: "proposed"});
  assert.equal(proposalReference({...value, review_url: "https://outside.test/?token=secret"}), null);
  assert.equal(proposalReference({...value, status: "success-assumed"}), null);
  assert.equal(proposalReference({...value, id: "../other"}), null);
});

test("confirmation requires global management permission", () => {
  assert.equal(canManageGrafana({permissions: ["*"], authorization_scope: {all: true}}), true);
  assert.equal(canManageGrafana({permissions: ["metrics.read"], authorization_scope: {all: true}}), false);
  assert.equal(canManageGrafana({permissions: ["metrics.manage"], authorization_scope: {all: false}}), false);
});

test("AI cards open only native saved URLs and keep pending proposals distinct", () => {
  const id = "12345678-1234-1234-1234-123456789abc";
  const proposal = {id, resource_kind:"dashboard", status:"applied", review_url:`/dashboards?change=${id}`,
    definition:{title:"Interfaces"}, resource_url:"https://icheck.test/grafana/d/native"};
  assert.deepEqual(grafanaResourceLinks(proposal), [{title:"Interfaces", url:proposal.resource_url}]);
  assert.deepEqual(grafanaResourceLinks({...proposal, status:"proposed"}), []);
  const result = {dashboards:[{title:"CPU", url:"https://icheck.test/grafana/d/linux"}]};
  assert.deepEqual(grafanaResourceLinks(result, "grafana.dashboards.search"), [{title:"CPU", url:result.dashboards[0].url}]);
  assert.deepEqual(grafanaResourceLinks(result, "inventory.devices.list"), []);
  for (const url of ["javascript:alert(1)", "https://user:secret@icheck.test/grafana/d/x", "https://icheck.test/grafana/d/x?token=secret", "https://icheck.test/other"]) {
    assert.deepEqual(grafanaResourceLinks({url}, "grafana.dashboard.link"), []);
  }
  const url = "https://icheck.test/grafana/d/linux?from=now-1h&to=now&var-device=lab";
  assert.equal(grafanaResourceLinks({url}, "grafana.dashboard.link")[0].url, url);
});

test("token settings clear secrets on submission and workspace changes without browser storage", () => {
  const source = readFileSync(new URL("../components/grafana-settings.tsx", import.meta.url), "utf8");
  for (const term of ['type="password"', 'autoComplete="off"', 'setToken("")', 'setRotations({})',
                      'icheck:namespace-changed', 'SESSION_CHANGE_KEY', 'expected_revision', 'shared_dataset_acknowledged']) assert.ok(source.includes(term));
  assert.doesNotMatch(source, /localStorage\.setItem|sessionStorage|Authorization.*Bearer/);
});

test("the native proposal workspace previews, explicitly confirms and restores without custom charts", () => {
  const source = readFileSync(new URL("../app/dashboards/page.tsx", import.meta.url), "utf8");
  for (const term of ['expected_plan_hash', 'checked={approved}', 'Confirm and apply', 'restore-preview',
                      'Inspect uncertain result', 'global', 'previous_resource', 'Advanced exact definition',
                      'Saved time range', 'Browser auto-refresh', 'Proposed dashboard display settings']) assert.ok(source.includes(term));
  assert.doesNotMatch(source, /iframe|recharts|dangerouslySetInnerHTML|sessionStorage/);
});
