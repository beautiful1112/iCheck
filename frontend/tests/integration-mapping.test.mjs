import assert from "node:assert/strict";
import test from "node:test";
import {readFileSync} from "node:fs";
import {mappingApproval, mappingLabel, suggestedChoices} from "../lib/integration-mapping.ts";

const asset = {id: "device", name: "Switch", enabled: true, revision: 3, identity_revision: 2};
const row = {resource_id: "resource", remote_id: "100", name: "Switch", current: true,
  binding_revision: 0, state: "unlinked", suggestion: asset, device: null, match: "exact_name", reason: null};
const view = {items: [row], can_link: true, scan_id: "scan", connection_revision: 4};

test("bulk approval pins connection, scan, binding and asset identity revisions", () => {
  assert.deepEqual(mappingApproval(view, suggestedChoices(view)), {
    expected_revision: 4, expected_scan_id: "scan", confirm: true, items: [{
      resource_id: "resource", source_name: "Switch", expected_binding_revision: 0,
      device_id: "device", expected_device_revision: 3, expected_device_identity_revision: 2,
    }],
  });
});

test("suggestions exclude ambiguous, retained and already linked resources", () => {
  assert.deepEqual(suggestedChoices({...view, can_link: false}), {});
  assert.deepEqual(suggestedChoices({...view, items: [
    {...row, suggestion: null, match: "ambiguous"}, {...row, current: false}, {...row, state: "linked"},
  ]}), {});
});

test("stale, empty, disabled, substituted and duplicate approvals are blocked locally", () => {
  assert.throws(() => mappingApproval({...view, can_link: false}, {resource: asset}), /completed/);
  assert.throws(() => mappingApproval({...view, scan_id: null}, {resource: asset}), /completed/);
  assert.throws(() => mappingApproval(view, {}), /Choose/);
  assert.throws(() => mappingApproval(view, {resource: {...asset, enabled: false}}), /available/);
  assert.throws(() => mappingApproval(view, {other: asset}), /available/);
  assert.throws(() => mappingApproval({...view, items: [row, {...row, resource_id: "other"}]}, {resource: asset, other: asset}), /only once/);
});

test("one thousand resources require one approval payload, not one thousand requests", () => {
  const items = Array.from({length: 1000}, (_, i) => ({...row, resource_id: `r${i}`, suggestion: {...asset, id: `d${i}`}}));
  const batch = {...view, items};
  assert.equal(mappingApproval(batch, suggestedChoices(batch)).items.length, 1000);
});

test("status explains stale evidence without claiming healthy devices or deleting links", () => {
  assert.equal(mappingLabel({...row, state: "linked"}), "Linked");
  assert.match(mappingLabel({...row, reason: "source_name_changed"}), /review/);
  assert.match(mappingLabel({...row, reason: "not_seen_in_latest_scan"}), /Not seen/);
  assert.match(mappingLabel({...row, match: "ambiguous"}), /Ambiguous/);
});

test("mapping has a separate tab, bulk review and session-bound reads without browser persistence", () => {
  const source = readFileSync(new URL("../components/integration-mapping.tsx", import.meta.url), "utf8");
  const parent = readFileSync(new URL("../components/monitoring-integrations.tsx", import.meta.url), "utf8");
  assert.match(parent, /"mapping", "Asset mapping"/);
  assert.match(source, /Select all/); assert.match(source, /I reviewed/); assert.match(source, /Unlink asset/);
  assert.match(source, /serial === epochRef.current/); assert.match(source, /mounted.current/);
  assert.match(source, /request === requests.current/);
  assert.doesNotMatch(source, /localStorage|sessionStorage|\/syncs|\/preview/);
});
