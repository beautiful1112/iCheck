import assert from "node:assert/strict";
import { test } from "node:test";
import { topologyEdgePaths } from "../lib/topology-edge-paths.ts";

const positions = new Map([["device", { x: 0, y: 0 }], ["endpoint", { x: 100, y: 0 }]]);
const edge = (id, source = "device", target = "endpoint") => ({ id, source, target });

test("single link stays straight", () => {
  assert.equal(topologyEdgePaths([edge("a")], positions).get("a"), "M 0 0 L 100 0");
});
test("parallel VLAN links retain distinct identities and symmetric paths", () => {
  const result = topologyEdgePaths([edge("a"), edge("b"), edge("c")], positions);
  assert.equal(result.size, 3);
  assert.equal(new Set(result.values()).size, 3);
  assert.equal(result.get("a"), "M 0 0 Q 50 -18 100 0");
  assert.equal(result.get("c"), "M 0 0 Q 50 18 100 0");
});
test("lane assignment is stable across response reorder and never mutates inputs", () => {
  const rows = Object.freeze([Object.freeze(edge("b")), Object.freeze(edge("a"))]);
  assert.deepEqual(topologyEdgePaths(rows, positions), topologyEdgePaths([...rows].reverse(), positions));
  assert.equal(rows[0].id, "b");
});
test("reverse directed link does not overlap its forward sibling", () => {
  const result = topologyEdgePaths([edge("a"), edge("b", "endpoint", "device")], positions);
  assert.equal(result.get("a"), "M 0 0 Q 50 -9 100 0");
  assert.equal(result.get("b"), "M 100 0 Q 50 9 0 0");
});
test("different node pairs are grouped without delimiter collisions", () => {
  const p = new Map([["a,b", { x: 0, y: 0 }], ["c", { x: 10, y: 0 }], ["a", { x: 0, y: 1 }], ["b,c", { x: 10, y: 1 }]]);
  const result = topologyEdgePaths([edge("a", "a,b", "c"), edge("b", "a", "b,c")], p);
  assert.equal(result.get("a"), "M 0 0 L 10 0");
  assert.equal(result.get("b"), "M 0 1 L 10 1");
});
test("large cohorts remain bounded but every visible link gets a path", () => {
  const result = topologyEdgePaths(Array.from({ length: 1000 }, (_, i) => edge(String(i))), positions);
  assert.equal(result.size, 1000);
  assert.equal(new Set(result.values()).size, 1000);
  for (const path of result.values()) {
    const y = Number(path.split(" ")[5]);
    assert.ok(Math.abs(y) <= 80);
    assert.ok(!path.includes("NaN"));
  }
});
test("self and coincident links are finite distinct loops", () => {
  const result = topologyEdgePaths([edge("a", "device", "device"), edge("b", "device", "device")], positions);
  assert.equal(result.size, 2);
  assert.equal(new Set(result.values()).size, 2);
  assert.ok([...result.values()].every(path => path.includes(" C ") && !path.includes("NaN")));
});
test("missing and non-finite positions are not rendered as invented links", () => {
  assert.equal(topologyEdgePaths([edge("a", "missing")], positions).size, 0);
  assert.equal(topologyEdgePaths([edge("a")], new Map([...positions, ["endpoint", { x: NaN, y: 0 }]])).size, 0);
});
test("Studio preview uses its smaller curve budget", () => {
  const result = topologyEdgePaths(Array.from({ length: 32 }, (_, i) => edge(String(i))), positions, 10, 36);
  assert.equal(result.size, 32);
  assert.ok([...result.values()].every(path => Math.abs(Number(path.split(" ")[5])) <= 36));
});
