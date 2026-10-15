import assert from "node:assert/strict";
import {test} from "node:test";
import {templateSummary, testedTemplate} from "../lib/http-monitor.ts";

const spec = {mode: "api", scheme: "https", method: "GET", path: "/stats", auth_mode: "basic", metrics: [{name: "queue_depth", value_pointer: "/queue", type: "gauge"}]};
test("HTTP preview explains request, auth and numeric mappings without secret values", () => {
  assert.deepEqual(templateSummary(spec), {request: "GET HTTPS /stats", authentication: "basic", metrics: ["queue_depth: /queue"]});
  assert.deepEqual(templateSummary({...spec, mode: "probe", metrics: []}).metrics, ["Request success", "Status code", "Latency", "TLS certificate expiry"]);
});
test("TCP or exporter up and stale/failed test are not a successful API measurement", () => {
  assert.equal(testedTemplate("verified", {check: "tcp_connect", success: true}, spec), false);
  assert.equal(testedTemplate("verified", {check: "http_metric_query", success: true, metric_samples: 0}, spec), false);
  assert.equal(testedTemplate("pending", {check: "http_metric_query", success: true, metric_samples: 1, metric_names: ["queue_depth"]}, spec), false);
  assert.equal(testedTemplate("verified", {check: "http_metric_query", success: true, metric_samples: 1, metric_names: ["queue_depth"]}, spec), true);
});
