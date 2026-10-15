import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {backupReceipt, backupDownloadPath, investigationBackups} from "../lib/configuration-backups.ts";

const id = "11111111-1111-4111-8111-111111111111";
const callId = "22222222-2222-4222-8222-222222222222";
const backupId = "33333333-3333-4333-8333-333333333333";
const deviceId = "44444444-4444-4444-8444-444444444444";
const receipt = {backup_id:backupId, created_at:"2026-10-13T12:00:00.123456+00:00", sha256:"a".repeat(64), bytes:32};
const call = {id:callId, investigation_id:id, tool_name:"extensions.network_checks.backup_configuration", status:"succeeded", arguments:{device_id:deviceId}, result:receipt};
const evidence = {investigation_id:id, evidence_type:"native_mcp_result", evidence_id:`extension:${deviceId}:${backupId}:${callId}`};

test("backup receipts have exact bounded metadata and a fixed protected API path", () => {
  assert.deepEqual(backupReceipt(receipt), receipt);
  assert.equal(backupDownloadPath(receipt), `/capability-studio/configuration-backups/${backupId}/download`);
  for (const invalid of [null, [], {...receipt, body:"secret configuration"}, {...receipt, url:"https://outside.test"},
    {...receipt, backup_id:"../other"}, {...receipt, created_at:"yesterday"}, {...receipt, created_at:"2026-99-99T12:00:00Z"},
    {...receipt, bytes:0}, {...receipt, bytes:1.5}, {...receipt, bytes:1_000_001}, {...receipt, sha256:"bad"}]) {
    assert.equal(backupReceipt(invalid), null);
  }
  assert.throws(() => backupDownloadPath({...receipt, backup_id:"../../secret"}));
});

test("Operator requires successful installed-call evidence in the same investigation", () => {
  const results = investigationBackups(id, [call], [evidence]);
  assert.equal(results.length, 1);
  assert.equal(results[0].deviceId, deviceId);
  assert.deepEqual(results[0].receipt, receipt);
  for (const changed of [{...call,status:"failed"}, {...call,status:"running"}, {...call,investigation_id:backupId},
    {...call,tool_name:"inventory.get_device"}, {...call,arguments:{device_id:"bad"}}, {...call,result:{interfaces:[]}}]) {
    assert.deepEqual(investigationBackups(id, [changed], [evidence]), []);
  }
  for (const changed of [{...evidence,investigation_id:backupId}, {...evidence,evidence_type:"model_summary"},
    {...evidence,evidence_id:`extension:${deviceId}:${backupId}:${backupId}`}, {...evidence,evidence_id:`extension:invalid:${backupId}:${callId}`}]) {
    assert.deepEqual(investigationBackups(id, [call], [changed]), []);
  }
  assert.deepEqual(investigationBackups(id, [call], []), []);
  assert.equal(investigationBackups(id, [call,call], [evidence]).length, 1);
});

test("download UI uses authenticated context-aware blobs and never renders configuration bodies", () => {
  const component=readFileSync(new URL("../components/configuration-backups.tsx",import.meta.url),"utf8");
  assert.match(component,/apiBlob\(backupDownloadPath\(receipt\)\)/);
  assert.match(component,/current !== epoch.current/);
  assert.match(component,/blob.size !== receipt.bytes/);
  assert.match(component,/URL.revokeObjectURL/);
  assert.match(component,/disabled=\{!canDownload \|\| busy\}/);
  assert.doesNotMatch(component,/blob\.text\(|localStorage|sessionStorage|dangerouslySetInnerHTML|fetch\(/);
  const studio=readFileSync(new URL("../components/studio-extension.tsx",import.meta.url),"utf8");
  assert.match(studio,/\/studio\/mcp\/test\?artifact=/);
  assert.match(studio,/Optional device test and backup history/);
  assert.doesNotMatch(studio,/ProtectedBackupDownload/);
  assert.doesNotMatch(studio,/href=.*configuration-backups/);
  const tests=readFileSync(new URL("../app/studio/mcp/test/page.tsx",import.meta.url),"utf8");
  assert.match(tests,/<ProtectedBackupDownload receipt=\{receipt\}/);
  assert.doesNotMatch(tests,/href=.*configuration-backups/);
  const operator=readFileSync(new URL("../app/page.tsx",import.meta.url),"utf8");
  assert.match(operator,/ConfigurationBackups investigationId=\{detail.investigation.id\}/);
  assert.match(operator,/canDownload=\{permits\(principal, "assets.read", "capabilities.manage"\)\}/);
  assert.match(operator,/className="min-w-0">\s*<div className="mb-3 flex items-center justify-between">\s*<div className="flex items-center gap-2">\s*<Database/);
});
