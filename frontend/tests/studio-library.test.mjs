import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import test from "node:test";
import {categoryOf, capabilityState, latestVersion, conversationLink, legacyStudioDestination, partitionMCPDrafts, mcpTools} from "../lib/studio-library.ts";

const id = "11111111-1111-4111-8111-111111111111";
const draft = {id, name:"demo", kind:"tool", description:"", labels:{format:"icheck.mcp-extension/v1", studio_session_id:id}, versions:[{id:"v2", version:2,status:"validated"},{id:"v1",version:1,status:"published"}]};
test("categorize executable MCP drafts separately from contracts and collectors", () => {
  assert.equal(categoryOf(draft), "mcp");
  assert.equal(categoryOf({...draft,labels:{},versions:[{definition:{format_version:"icheck.mcp-extension/v1"}}]}),"mcp");
  for (const [kind, category] of Object.entries({collector:"collectors",tool:"tools",workflow:"automation",skill:"automation",topology:"other",report:"other"})) {
    assert.equal(categoryOf({...draft,labels:{},kind}),category);
  }
});
test("unknown or inaccessible installation state is never rendered as not installed", () => {
  assert.equal(capabilityState(draft,null),"Installation status unavailable");
  assert.equal(capabilityState(draft,[]),"Not installed");
  assert.equal(capabilityState(draft,[{artifact_id:"different",enabled:true}]),"Not installed");
  for(const enabled of [true,false]) assert.equal(capabilityState(draft,[{artifact_id:id,active_version_id:"v1",enabled}]),`Installed · ${enabled?"Enabled":"Disabled"}`);
  assert.equal(latestVersion(draft).id,"v2");
  assert.equal(capabilityState({...draft,labels:{},kind:"collector"},[]),"Published template");
});
test("conversation links use persisted identity, not draft names or a capped session search", () => {
  assert.equal(conversationLink(draft),`/studio/builder?session=${id}`);
  assert.equal(conversationLink({...draft,labels:{studio_session_id:"//unsafe"}}),null);
});
test("old session, investigation, creation and pinned template links survive navigation separation", () => {
  for (const key of ["session","investigation","artifact"]) assert.equal(legacyStudioDestination(new URLSearchParams({[key]:id})),`/studio/builder?${key}=${id}`);
  assert.equal(legacyStudioDestination(new URLSearchParams({artifact:id,template_version:id})),`/studio/builder?artifact=${id}&template_version=${id}`);
  assert.equal(legacyStudioDestination(new URLSearchParams("create=extension")),"/studio/builder?create=extension");
  assert.equal(legacyStudioDestination(new URLSearchParams("session=//unsafe&redirect=https://evil.test")),null);
  assert.equal(legacyStudioDestination(new URLSearchParams()),null);
});
test("library, conversation, and MCP setup have separate boundaries", () => {
  const source = path => readFileSync(new URL(path,import.meta.url),"utf8");
  assert.doesNotMatch(source("../components/studio-library.tsx"),/StudioExtension|<Textarea|row.messages|\/generate/);
  assert.doesNotMatch(source("../app/studio/builder/page.tsx"),/<aside|<StudioExtension/);
  assert.match(source("../app/studio/mcp/page.tsx"),/<StudioExtension/);
  assert.match(source("../app/studio/conversations/page.tsx"),/Continue conversation/);
  assert.match(source("../components/studio-nav.tsx"),/item.id === "builder" \? <a/);
});
test("package approval is independent of device tests and internal SSH configuration", () => {
  const source=readFileSync(new URL("../components/studio-extension.tsx",import.meta.url),"utf8");
  assert.match(source,/Approve and install/);
  assert.match(source,/access_mode: "authorized_inventory"/);
  assert.match(source,/locked.current/);
  assert.match(source,/!restoreApproved/);
  assert.match(source,/Optional device test and backup history/);
  assert.doesNotMatch(source,/test_ids|selectedTests|StudioSSHIdentity|Find SSH devices|Authorized SSH target/);
  const diagnostics=readFileSync(new URL("../app/studio/mcp/test/page.tsx",import.meta.url),"utf8");
  assert.match(diagnostics,/Installation does not require these tests/);
  assert.match(diagnostics,/Run test and save backup/);
  assert.ok(!diagnostics.includes("extensions/install"));
});

const spec = {format_version:"icheck.mcp-extension/v1", spec:{tools:[
  {name:"get_interface_status",operation:"read",commands:["show interfaces status"]},
  {name:"backup_configuration",operation:"backup",commands:["show running-config"]},
]}};
test("a two-tool package remains one server across versions; a failed attempt is separate draft history", () => {
  const failed = {...draft,id:"failed",versions:[{id:"failed-v1",version:1,status:"draft",definition:spec}]};
  const server = {...draft,versions:draft.versions.map(v=>({...v,definition:spec}))};
  const {capabilities,drafts}=partitionMCPDrafts([failed,server],[]);
  assert.deepEqual(capabilities.map(row=>row.id),[id]);
  assert.deepEqual(drafts.map(row=>row.id),["failed"]);
  assert.equal(mcpTools(latestVersion(server)).length,2);
  assert.deepEqual(mcpTools(latestVersion(server)).map(tool=>tool.name),["get_interface_status","backup_configuration"]);
  assert.equal(failed.versions[0].status,"draft");
});
test("installed, deprecated and older-validated server packages are not hidden as failed drafts", () => {
  const older = {...draft,versions:[...draft.versions,{id:"v3",version:3,status:"draft"}]};
  const deprecated={...draft,versions:[{id:"v1",version:1,status:"deprecated"}]};
  const installed={...draft,versions:[{id:"v1",version:1,status:"draft"}]};
  for(const row of [older,deprecated]) assert.equal(partitionMCPDrafts([row],null).capabilities.length,1);
  assert.equal(partitionMCPDrafts([installed],[{artifact_id:id}]).capabilities.length,1);
  assert.equal(partitionMCPDrafts([{...draft,kind:"collector",labels:{},versions:[]}],[]).capabilities.length,1);
});
test("unavailable or malformed tool definitions cannot fabricate a zero-tool server", () => {
  for(const version of [undefined,{}, {definition:{}},{definition:{...spec,spec:{tools:[{}]}}}]) assert.equal(mcpTools(version),null);
  assert.equal(mcpTools({definition:spec})[1].operation,"backup");
});

test("SSH first use has explicit fingerprint review and reuses the saved identity", () => {
  const identity = readFileSync(new URL("../components/studio-ssh-identity.tsx",import.meta.url),"utf8");
  const extension = readFileSync(new URL("../components/studio-extension.tsx",import.meta.url),"utf8");
  assert.match(identity,/Confirm and save fingerprint/);
  assert.match(identity,/confirm && \(!approved/);
  assert.match(identity,/accept_changed: identity!\.state === "changed"/);
  assert.match(identity,/current === epoch.current/);
  assert.match(identity,/onConfirmed\(""\)/);
  assert.doesNotMatch(extension,/Verified SSH public host key|<Textarea|host_public_key: hostKey/);
  assert.doesNotMatch(extension,/<StudioSSHIdentity/);
  const access=readFileSync(new URL("../components/device-ssh-access.tsx",import.meta.url),"utf8");
  assert.match(access,/<StudioSSHIdentity/);
  assert.match(access,/independent of installing an MCP server/);
  const onboarding=readFileSync(new URL("../components/device-native-ssh.tsx",import.meta.url),"utf8");
  assert.match(onboarding,/!device.site \|\| row.site === device.site/);
});

test("legacy SSH is a device-local explicit profile, separate from fingerprint trust", () => {
  const identity = readFileSync(new URL("../components/studio-ssh-identity.tsx",import.meta.url),"utf8");
  assert.match(identity,/Modern SSH \(default\)/);
  assert.match(identity,/I accept legacy SSH risk for this device only/);
  assert.match(identity,/accept_legacy_risk: profile === "legacy_cisco_v1" && legacyApproved/);
  assert.match(identity,/profile === "legacy_cisco_v1" && !legacyApproved/);
  assert.match(identity,/base \+ "\/compatibility"/);
  assert.match(identity,/onConfirmed\("", true\)/);
  assert.match(identity,/ssh_profile_current/);
  assert.match(identity,/Host-key verification remains required/);
  const extension = readFileSync(new URL("../components/studio-extension.tsx",import.meta.url),"utf8");
  assert.doesNotMatch(extension,/test.binding_hash/);
});
