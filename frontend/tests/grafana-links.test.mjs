import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { grafanaOverviewHref, networkDashboardHref } from "../lib/grafana-links.ts";

test("contextual dashboards carry device and time only, never a token or renderer", () => {
  const url = new URL(networkDashboardHref("device-123", "now-6h"), "https://icheck.test");
  assert.equal(url.pathname, "/grafana/d/icheck-network");
  assert.equal(url.searchParams.get("var-device"), "device-123");
  assert.equal(url.searchParams.get("from"), "now-6h");
  assert.equal(url.searchParams.get("to"), "now");
  assert.deepEqual([...url.searchParams.keys()], ["var-device", "from", "to", "timezone"]);
  assert.equal(grafanaOverviewHref, "/grafana/d/icheck-collection");
});

test("device context cannot inject another URL parameter", () => {
  const id = "device&token=not-a-token";
  const url = new URL(networkDashboardHref(id), "https://icheck.test");
  assert.equal(url.searchParams.get("var-device"), id);
  assert.equal(url.searchParams.has("token"), false);
  assert.throws(() => networkDashboardHref("device", "javascript:alert(1)"));
  assert.throws(() => networkDashboardHref("device\n"));
  assert.throws(() => networkDashboardHref(""));
});

test("the operator and device UI use authenticated full-page links", () => {
  const read = file => readFileSync(new URL(file, import.meta.url), "utf8");
  const home = read("../app/page.tsx");
  const assets = read("../components/assets-workspace.tsx");
  assert.match(home, /label: "Dashboards"/);
  assert.match(home, /if \(item.external\)/);
  assert.match(home, /<a key=\{item.label\} href=\{item.href\}/);
  assert.match(assets, /<a href=\{networkDashboardHref\(device.id\)\}/);
  assert.doesNotMatch(read("../lib/grafana-links.ts"), /iframe|localStorage|sessionStorage|Bearer/);
});
