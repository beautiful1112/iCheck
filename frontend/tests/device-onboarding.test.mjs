import assert from "node:assert/strict";
import { test } from "node:test";

import {
  credentialReferenceEligible,
  eligibleCredentialProfiles,
  verificationMethodAvailable,
} from "../lib/device-onboarding.ts";

const profiles = [
  { id: "lab-snmp", name: "Lab SNMP", enabled: true,
    allowed_adapters: ["snmp_exporter"], worker_selector: { site: "LAB" } },
  { id: "other-snmp", name: "Other SNMP", enabled: true,
    allowed_adapters: ["snmp_exporter"], worker_selector: { site: "OTHER" } },
  { id: "lab-ssh", name: "Lab SSH", enabled: true,
    allowed_adapters: ["ssh"], worker_selector: { site: "LAB" } },
  { id: "extra-selector", name: "Extra worker label", enabled: true,
    allowed_adapters: ["snmp_exporter"], worker_selector: { site: "LAB", rack: "R1" } },
  { id: "disabled", name: "Disabled", enabled: false,
    allowed_adapters: ["snmp_exporter"], worker_selector: { site: "LAB" } },
  { id: "unscoped", name: "Unscoped", enabled: true,
    allowed_adapters: ["snmp_exporter"], worker_selector: {} },
];

test("onboarding offers only adapter and worker-selector compatible references", () => {
  assert.deepEqual(
    eligibleCredentialProfiles(profiles, "snmp_exporter", "LAB").map((item) => item.id),
    ["lab-snmp", "unscoped"],
  );
  assert.deepEqual(
    eligibleCredentialProfiles(profiles, "ssh", "LAB").map((item) => item.id),
    ["lab-ssh"],
  );
});

test("verification discovery distinguishes unsupported from unknown and respects site/state", () => {
  const workers = [{site:"LAB",state:"online",capabilities:["snmp_exporter","node_exporter"]},
    {site:"LAB",state:"offline",capabilities:["icmp"]},
    {site:"OTHER",state:"online",capabilities:["icmp"]}];
  assert.equal(verificationMethodAvailable(workers,"snmp_exporter","LAB"), true);
  assert.equal(verificationMethodAvailable(workers,"icmp","LAB"), false);
  assert.equal(verificationMethodAvailable(workers,"icmp","OTHER"), true);
  assert.equal(verificationMethodAvailable(workers,"icmp",""), true);
  assert.equal(verificationMethodAvailable([],"icmp","LAB"), false);
  assert.equal(verificationMethodAvailable(null,"icmp","LAB"), null);
  assert.equal(verificationMethodAvailable([{site:null,state:"online",capabilities:["icmp"],labels:{site:"LAB"}}],"icmp"," LAB "), true);
});

test("a selected reference becomes invalid when the site changes", () => {
  assert.equal(credentialReferenceEligible(profiles, "snmp_exporter", "LAB", "lab-snmp"), true);
  assert.equal(credentialReferenceEligible(profiles, "snmp_exporter", "LAB", "Lab SNMP"), true);
  assert.equal(credentialReferenceEligible(profiles, "snmp_exporter", "OTHER", "lab-snmp"), false);
  assert.equal(credentialReferenceEligible(profiles, "snmp_exporter", "LAB", "other-snmp"), false);
  assert.equal(credentialReferenceEligible(profiles, "snmp_exporter", "LAB", ""), true);
});
