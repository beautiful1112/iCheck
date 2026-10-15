import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { auditStandalone, packageStandalone, publicApiBase } from "../scripts/native-package.mjs";

test("native API base defaults to same origin and accepts only credential-free HTTPS API paths", () => {
  assert.equal(publicApiBase(), "/api/v1");
  assert.equal(publicApiBase("https://monitor.example.test/api/v1"), "https://monitor.example.test/api/v1");
  for (const value of ["//attacker/api/v1", "http://monitor/api/v1", "https://user:token@monitor/api/v1",
    "https://monitor/api/v1?token=private", "https://monitor/api/v1#secret", "https://monitor/wrong"]) {
    assert.throws(() => publicApiBase(value));
  }
});

function fixture() {
  const root = mkdtempSync(path.join(tmpdir(), "icheck-native-package-"));
  const project = path.join(root, "project"), standalone = path.join(project, ".next", "standalone");
  for (const directory of [path.join(standalone, ".next"), path.join(project, ".next", "static"),
    path.join(project, "public"), path.join(project, "scripts")]) mkdirSync(directory, { recursive: true });
  writeFileSync(path.join(standalone, "server.js"), "export const packaged = true;\n");
  writeFileSync(path.join(standalone, "package.json"), '{"type":"module"}');
  writeFileSync(path.join(standalone, ".next", "BUILD_ID"), "controlled-build");
  writeFileSync(path.join(project, ".next", "BUILD_ID"), "controlled-build");
  writeFileSync(path.join(project, ".next", "static", "client.js"), "controlled-static");
  writeFileSync(path.join(project, "public", "favicon.svg"), "controlled-icon");
  writeFileSync(path.join(project, "scripts", "native-server.mjs"), "controlled-runner");
  writeFileSync(path.join(project, ".next", "icheck-native-build.json"), JSON.stringify({
    format_version: "icheck.native-frontend/v1", api_base_url: "/api/v1", version: "fixture", build_id: "controlled-build" }));
  return { root, project, standalone, destination: path.join(root, "release") };
}

test("standalone package carries server, static/public assets, runner and writable cache without the workspace", () => {
  const f = fixture();
  try {
    const result = packageStandalone(f.project, f.destination);
    assert.ok(result.files > 0);
    rmSync(f.project, { recursive: true });
    assert.equal(readFileSync(path.join(f.destination, ".next", "static", "client.js"), "utf8"), "controlled-static");
    assert.ok(existsSync(path.join(f.destination, "public", "favicon.svg")));
    assert.ok(existsSync(path.join(f.destination, ".next", "cache")));
    assert.equal(JSON.parse(readFileSync(path.join(f.destination, "native-release.json"), "utf8")).api_base_url, "/api/v1");
    assert.throws(() => packageStandalone(f.destination, f.destination), /already exists/);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test("packaging refuses escaping links and environment files instead of shipping private or external content", () => {
  const f = fixture();
  try {
    const outside = path.join(f.root, "outside"); writeFileSync(outside, "not-for-package");
    symlinkSync(outside, path.join(f.standalone, "escape"));
    assert.throws(() => auditStandalone(f.standalone), /escaping symlink/);
    assert.throws(() => packageStandalone(f.project, f.destination), /escaping symlink/);
    assert.ok(!existsSync(f.destination));
    rmSync(path.join(f.standalone, "escape"));
    writeFileSync(path.join(f.standalone, ".env.production"), "private");
    assert.throws(() => packageStandalone(f.project, f.destination), /Environment files/);
    assert.ok(!existsSync(f.destination));
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test("packaging rejects a stale server or manifest from another framework build", () => {
  const f = fixture();
  try {
    writeFileSync(path.join(f.standalone, ".next", "BUILD_ID"), "other-build");
    assert.throws(() => packageStandalone(f.project, f.destination), /same build/);
    assert.ok(!existsSync(f.destination));
    writeFileSync(path.join(f.standalone, ".next", "BUILD_ID"), "controlled-build");
    writeFileSync(path.join(f.project, ".next", "BUILD_ID"), "other-build");
    assert.throws(() => packageStandalone(f.project, f.destination), /same build/);
    assert.ok(!existsSync(f.destination));
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});
