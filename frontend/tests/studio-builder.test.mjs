import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import test from "node:test";
import {authoringKind, canPublish, credentialFreeTarget, inferTask, legacyKind, previewFacts,
  publishedVersion, runtimeLink, validReference, isHTTPMonitoring, isSNMPMonitoring, isMonitoring,
  isExporterMonitoring, monitoringPlugin, inferMonitoringSource} from "../lib/studio-builder.ts";
import {defaultMonitoringProfile, exporterCollectors, exporterProtocol} from "../lib/exporter-monitor.ts";

const id = "11111111-1111-4111-8111-111111111111";
const admin = {permissions: ["capabilities.manage"], authorization_scope: {all: true}, subject: "fixture"};
const draft = {id, title: "Fixture", artifact_kind: "collector", status: "validated", artifact_version_id: id,
  target_url: "https://example.test/inventory", brief: "Requested interval: 60 seconds\nCredential reference: profile-1",
  current_spec: {field_mappings: [{destination_field: "mac_address"}]}, messages: [{structured_content: {artifact_version_id: id, validation_report: {publication_blocked: false}}}]};

test("shared monitoring target search is bounded, read-only and discards superseded choices", () => {
  const source = readFileSync(new URL("../components/studio-monitoring-target.tsx", import.meta.url), "utf8");
  assert.match(source, /Find registered targets/);
  assert.match(source, /type="search" maxLength=\{200\}/);
  assert.match(source, /new URLSearchParams\(\{search: targetSearch\}\)/);
  assert.match(source, /if \(!active \|\| context !== epoch.current\) return/);
  assert.match(source, /return \(\) => \{active = false; window.clearTimeout\(timer\);\}/);
  const handler = source.slice(source.indexOf("function findTargets"), source.indexOf("useEffect(() => {const timer = window.setTimeout(() => setVersion"));
  assert.match(handler, /setSelected\(""\)/);
  assert.match(handler, /setState\(null\)/);
  assert.match(handler, /setApproved\(false\)/);
  assert.doesNotMatch(handler, /apiFetch|testTarget|enable\(/);
  assert.doesNotMatch(source, /Use Assets to find targets outside this list/);
});

test("task intents replace implementation-type selection and infer workflow/Skill/extensions", () => {
  assert.equal(inferTask("Build interface panels in Grafana", null), "dashboard");
  assert.equal(inferTask("Create a reusable diagnostic skill", null), "automate");
  assert.equal(inferTask("Monitor the controller API", null), "monitor");
  assert.equal(inferTask("Monitor this API and make a dashboard", "monitor"), "monitor");
  assert.equal(authoringKind("Create a diagnostic skill"), "skill");
  assert.equal(authoringKind("Run a workflow every day"), "workflow");
  assert.equal(authoringKind("Describe an MCP tool contract"), "tool");
  assert.equal(inferTask("Build a Netmiko MCP server for interface checks", null), "extension");
  assert.equal(inferTask("Check existing MCP server health", null), "automate");
});
test("MCP installation rejects stale runtime reads and needs no device selection", () => {
  const source = readFileSync(new URL("../components/studio-extension.tsx", import.meta.url), "utf8");
  assert.match(source, /request !== reads.current/);
  assert.match(source, /epoch !== generation.current/);
  assert.match(source, /setConfigured\(false\); setInstalled\(null\)/);
  assert.match(source, /expected_revision: installed\?\.revision \|\| 0/);
  assert.doesNotMatch(source, /extensions\/targets|test_ids|selectedTests/);
});
test("executable extension preview cannot claim installation or use generic template publication", () => {
  const extension = {...draft, artifact_kind: "tool", current_spec: {format_version: "icheck.mcp-extension/v1",
    device_type: "cisco_ios", tools: [{name: "backup_configuration", operation: "backup"}]}};
  assert.match(previewFacts(extension).result, /draft fixture checks passed; installation is managed separately/);
  assert.match(previewFacts(extension).outcomes[0], /protected configuration backup receipt/);
  assert.equal(canPublish(extension, admin), false);
});
test("exact-current validation, human management and global scope gate publication", () => {
  assert.equal(canPublish(draft, admin), true);
  for (const row of [{...draft, status: "draft"}, {...draft, artifact_version_id: "other"},
    {...draft, artifact_kind: "visualization"}, {...draft, artifact_kind: "report"},
    {...draft, messages: [{structured_content: {artifact_version_id: id, validation_report: {publication_blocked: true}}}]}]) {
    assert.equal(canPublish(row, admin), false);
  }
  assert.equal(canPublish(draft, {...admin, authorization_scope: {sites: ["LAB"]}}), false);
  assert.equal(canPublish(draft, {...admin, permissions: []}), false);
});
test("preview exposes intent but never equates publication with live monitoring", () => {
  assert.deepEqual(previewFacts(draft).outcomes, ["mac_address"]);
  assert.equal(previewFacts(draft).interval, "60");
  assert.equal(previewFacts(draft).credential, "profile-1");
  assert.match(previewFacts({...draft, status: "published"}).result, /activation is separate/);
});
test("runtime links pin a published UUID, and cannot use legacy or draft versions", () => {
  const cap = {kind: "workflow", versions: [{id, version: 1, status: "published"}, {id: "draft", version: 2, status: "draft"}]};
  assert.equal(publishedVersion(cap).version, 1);
  assert.equal(runtimeLink(cap), `/?workflow_version=${id}`);
  assert.equal(runtimeLink({...cap, kind: "visualization"}), null);
  assert.equal(runtimeLink({...cap, versions: [{id: "../../escape", version: 1, status: "published"}]}), null);
  assert.equal(validReference("../../escape"), false);
  assert.equal(legacyKind("report"), true);
});
test("collector target URLs cannot carry credentials or browser fragments", () => {
  assert.equal(credentialFreeTarget("https://api.example.test/v1"), "https://api.example.test/v1");
  for (const url of ["https://user:pass@api.example.test", "https://api.example.test?access_token=secret", "https://api.example.test#password", "file:///etc/passwd"]) {
    assert.throws(() => credentialFreeTarget(url));
  }
});
test("native HTTP monitoring exposes numeric mappings and pins the published template version", () => {
  const native = {...draft, current_spec: {contract: "icheck.http-monitoring-authoring/v1", metrics: [{name: "queue_depth", value_pointer: "/queue/depth"}]}};
  assert.equal(isHTTPMonitoring(native), true);
  assert.deepEqual(previewFacts(native).outcomes, ["queue_depth: /queue/depth"]);
  const cap = {id, kind: "collector", versions: [{id, version: 1, status: "published", collector_definition: {adapter_type: "http_metrics"}}]};
  assert.equal(runtimeLink(cap), `/studio?artifact=${id}&template_version=${id}`);
  assert.equal(runtimeLink({...cap, id: "../unsafe"}), null);
});
test("retired routes redirect, and the operator has no Service Intelligence dependency", () => {
  const root = new URL("../", import.meta.url);
  const home = readFileSync(new URL("app/page.tsx", root), "utf8");
  assert.match(home, /operator\/summary/);
  assert.doesNotMatch(home, /recent_situations|dashboard\/summary|href: "\/services"|visualization-proposal/);
  for (const [path, target] of [["services", "/assets/devices"], ["visualizations", "/grafana/d/icheck-collection"], ["situations", "/alerts"], ["studio/visualization-proposals", "/dashboards"]]) {
    const page = readFileSync(new URL(`app/${path}/page.tsx`, root), "utf8");
    assert.ok(page.includes(`redirect("${target}")`));
    assert.doesNotMatch(page, /apiFetch|recharts|polyline/);
  }
});
test("SNMP uses the same monitoring workflow and exact published library link", () => {
  const native={...draft,current_spec:{contract:"icheck.snmp-monitoring-authoring/v1",symbols:["SNMPv2-MIB::sysUpTime"]}};
  assert.equal(isSNMPMonitoring(native),true);
  assert.equal(isMonitoring(native),true);
  assert.deepEqual(previewFacts(native).outcomes,["SNMPv2-MIB::sysUpTime"]);
  assert.match(previewFacts(native).result,/no live collection proof/);
  assert.equal(runtimeLink({id,kind:"collector",versions:[{id,version:1,status:"published",validation_report:{plugin:"snmp"}}]}),`/studio?artifact=${id}&template_version=${id}`);
});
test("Linux and Windows reuse Studio testing and exact published library links", () => {
  for (const plugin of ["linux", "windows"]) {
    const native = {...draft, current_spec: {contract: "icheck.exporter-monitoring-authoring/v1", groups: ["cpu", "uptime"]},
      messages: [{role: "system", structured_content: {exporter_monitoring_input: {plugin}}}]};
    assert.equal(isExporterMonitoring(native), true);
    assert.equal(isMonitoring(native), true);
    assert.equal(monitoringPlugin(native), plugin);
    assert.equal(inferMonitoringSource(`Monitor ${plugin} CPU and uptime`), plugin);
    assert.match(previewFacts(native).outcomes[0], /actual samples required/);
    assert.equal(runtimeLink({id,kind:"collector",versions:[{id,version:1,status:"published",validation_report:{plugin}}]}), `/studio?artifact=${id}&template_version=${id}`);
  }
  assert.deepEqual(exporterCollectors({plugin: "linux", groups: ["cpu", "uptime", "cpu"]}), ["cpu", "stat", "time"]);
  assert.deepEqual(exporterCollectors({plugin: "windows", groups: ["disk", "network"]}), ["logical_disk", "net"]);
});
test("native monitoring forms share protocol-specific profile defaults", () => {
  for (const [protocol, profile] of Object.entries({snmp:"preview-snmp",https_api:"preview-http",
    node_exporter:"preview-linux",windows_exporter:"preview-windows",cadvisor:"preview-containers",vmware_exporter:"preview-vmware"})) {
    assert.equal(defaultMonitoringProfile(protocol), profile);
  }
  assert.deepEqual(exporterCollectors({plugin:"linux",groups:["cpu","memory","uptime"]}), ["cpu","meminfo","stat","time"]);
  assert.deepEqual(exporterCollectors({plugin:"windows",groups:["disk","network","uptime"]}), ["logical_disk","net","system"]);
});

test("container monitoring is inferred before Linux and keeps the shared template workflow", () => {
  const native = {...draft,current_spec:{contract:"icheck.exporter-monitoring-authoring/v1",groups:["cpu","memory"]},
    messages:[{role:"system",structured_content:{exporter_monitoring_input:{plugin:"containers"}}}]};
  assert.equal(inferMonitoringSource("Monitor Linux Docker container CPU and memory"),"containers");
  assert.equal(monitoringPlugin(native),"containers");
  assert.equal(isMonitoring(native),true);
  assert.deepEqual(exporterCollectors({plugin:"containers",groups:["cpu","memory","uptime"]}),["cpu","memory","metadata"]);
  assert.equal(exporterProtocol("containers"),"cadvisor");
  assert.equal(runtimeLink({id,kind:"collector",versions:[{id,version:1,status:"published",validation_report:{plugin:"containers"}}]}),`/studio?artifact=${id}&template_version=${id}`);
  assert.match(previewFacts(native).result,/no live collection proof/);
});
test("VMware reuses the builder and pins the selected object scope", () => {
  const native={...draft,current_spec:{contract:"icheck.exporter-monitoring-authoring/v1",groups:["cpu","memory"]},
    messages:[{role:"system",structured_content:{exporter_monitoring_input:{plugin:"vmware"}}}]};
  assert.equal(inferMonitoringSource("Monitor an ESXi VMware host and its Windows VM"),"vmware");
  assert.equal(monitoringPlugin(native),"vmware");
  assert.equal(isMonitoring(native),true);
  assert.equal(exporterProtocol("vmware"),"vmware_exporter");
  assert.deepEqual(exporterCollectors({plugin:"vmware",vmware_scope:"vms",groups:["cpu","disk"]}),["vms"]);
  assert.deepEqual(exporterCollectors({plugin:"vmware",vmware_scope:"datastores",groups:["disk"]}),["datastores"]);
  assert.equal(runtimeLink({id,kind:"collector",versions:[{id,version:1,status:"published",validation_report:{plugin:"vmware"}}]}),`/studio?artifact=${id}&template_version=${id}`);
  assert.match(previewFacts(native).result,/no live collection proof/);
});
