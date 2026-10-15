import assert from "node:assert/strict";
import test from "node:test";
import {publicSource, researchSources} from "../lib/research.ts";

test("reference links reject script and credentialed URLs", () => {
  for (const url of ["javascript:alert(1)", "file:///etc/passwd", "https://user:secret@example.com/", "http://example.com/"]) {
    assert.equal(publicSource({url}), null);
  }
});

test("source list combines retained references and exact fetched hashes", () => {
  const url = "https://www.cisco.com/docs";
  const result = researchSources({public_research: {sources: [{title: "Cisco", url}]},
    research_documents: [{url, title: "Cisco reference", sha256: "a".repeat(64)}],
    snmp_monitoring_input: {research_sources: [{module: "IP-MIB", url: "https://raw.githubusercontent.com/cisco/cisco-mibs/main/v2/IP-MIB.my"}]}});
  assert.equal(result.length, 2);
  assert.equal(result[0].sha256, "a".repeat(64));
  assert.equal(result[1].title, "IP-MIB");
});
