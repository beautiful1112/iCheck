import test from "node:test";
import assert from "node:assert/strict";
import {
  chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync,
  rmSync, statSync, symlinkSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { stageNativeFrontend } from "../stage_native_frontend.mjs";
import { packagePermissions } from "../native_frontend_permissions.mjs";

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "icheck-native-stage-"));
  const source = join(root, "source"), destination = join(root, "installed");
  mkdirSync(join(source, ".next", "cache"), { recursive: true });
  mkdirSync(join(source, "public"));
  writeFileSync(join(source, "native-release.json"), JSON.stringify({
    format_version: "icheck.native-frontend/v1", build_id: "fixture-build", api_base_url: "/api/v1", files: 7,
  }));
  writeFileSync(join(source, ".next", "BUILD_ID"), "fixture-build\n");
  writeFileSync(join(source, "start.mjs"), "export const native = true;\n");
  writeFileSync(join(source, "public", "favicon.svg"), "<svg/>\n");
  return { root, source, destination, ids: {
    packageUid: process.getuid(), packageGid: process.getgid(),
    serviceUid: process.getuid(), serviceGid: process.getgid(),
  } };
}

test("first install is byte-equal, immutable except for service-owned cache, and never overwrites", () => {
  const f = fixture();
  try {
    const result = stageNativeFrontend(f.source, f.destination, f.ids);
    assert.equal(result.build_id, "fixture-build");
    assert.equal(result.files_byte_compared, 4);
    assert.equal(result.bytes_compared > 0, true);
    assert.equal(statSync(f.destination).mode & 0o777, 0o555);
    assert.equal(statSync(join(f.destination, "start.mjs")).mode & 0o777, 0o444);
    assert.equal(statSync(join(f.destination, ".next", "cache")).mode & 0o777, 0o700);
    assert.equal(statSync(join(f.destination, ".next", "cache")).uid, f.ids.serviceUid);
    assert.equal(readFileSync(join(f.destination, "public", "favicon.svg"), "utf8"), "<svg/>\n");
    chmodSync(f.root, 0o755);
    const check = () => packagePermissions(f.destination, {
      serviceUid: f.ids.serviceUid, serviceGid: f.ids.serviceGid,
      packageUid: f.ids.packageUid, ancestorFloor: f.root,
    });
    assert.equal(check(), true);
    chmodSync(join(f.destination, "start.mjs"), 0o644);
    assert.equal(check(), false);
    chmodSync(join(f.destination, "start.mjs"), 0o444);
    chmodSync(join(f.destination, ".next", "cache"), 0o755);
    assert.equal(check(), false);
    chmodSync(join(f.destination, ".next", "cache"), 0o700);
    chmodSync(join(f.destination, ".next"), 0o755);
    rmSync(join(f.destination, ".next", "cache"), { recursive: true });
    chmodSync(join(f.destination, ".next"), 0o555);
    assert.equal(check(), false);
    chmodSync(join(f.destination, ".next"), 0o755);
    mkdirSync(join(f.destination, ".next", "cache"), { mode: 0o700 });
    chmodSync(join(f.destination, ".next"), 0o555);
    chmodSync(f.destination, 0o755);
    symlinkSync(".next/cache", join(f.destination, "cache-alias"));
    chmodSync(f.destination, 0o555);
    assert.equal(check(), false);
    assert.throws(() => stageNativeFrontend(f.source, f.destination, f.ids), /already exists/);
    assert.equal(readFileSync(join(f.destination, "native-release.json"), "utf8"),
      readFileSync(join(f.source, "native-release.json"), "utf8"));
  } finally {
    if (existsSync(f.destination)) chmodSync(f.destination, 0o700);
    for (const path of [join(f.destination, "public"), join(f.destination, ".next")]) {
      if (existsSync(path)) chmodSync(path, 0o700);
    }
    rmSync(f.root, { recursive: true, force: true });
  }
});

test("invalid or used packages and existing links fail without claiming a destination", () => {
  const f = fixture();
  try {
    writeFileSync(join(f.source, ".next", "cache", "runtime-data"), "not for release");
    assert.throws(() => stageNativeFrontend(f.source, f.destination, f.ids), /used cache/);
    assert.equal(existsSync(f.destination), false);
    rmSync(join(f.source, ".next", "cache", "runtime-data"));
    writeFileSync(join(f.source, ".env.production"), "secret-shaped-value");
    assert.throws(() => stageNativeFrontend(f.source, f.destination, f.ids), /Environment files/);
    assert.equal(existsSync(f.destination), false);
    rmSync(join(f.source, ".env.production"));
    rmSync(join(f.source, ".next", "cache"), { recursive: true });
    symlinkSync("../public", join(f.source, ".next", "cache"));
    assert.throws(() => stageNativeFrontend(f.source, f.destination, f.ids), /incomplete or contains a used cache/);
    assert.equal(existsSync(f.destination), false);
    rmSync(join(f.source, ".next", "cache"));
    mkdirSync(join(f.source, ".next", "cache"));
    writeFileSync(join(f.source, "native-release.json"), JSON.stringify({
      format_version: "icheck.native-frontend/v1", build_id: "fixture-build", api_base_url: "http://unsafe/api/v1", files: 7,
    }));
    assert.throws(() => stageNativeFrontend(f.source, f.destination, f.ids), /requires HTTPS/);
    assert.equal(existsSync(f.destination), false);
    symlinkSync(join(f.root, "missing"), f.destination);
    assert.ok(lstatSync(f.destination).isSymbolicLink());
    assert.throws(() => stageNativeFrontend(f.source, f.destination, f.ids), /already exists/);
    assert.ok(lstatSync(f.destination).isSymbolicLink());
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test("failed ownership hardening cleans only its newly claimed destination", () => {
  const f = fixture();
  try {
    assert.throws(() => stageNativeFrontend(f.source, f.destination, {
      ...f.ids, serviceUid: Number.MAX_SAFE_INTEGER,
    }), /out of range|invalid|EINVAL/i);
    assert.equal(existsSync(f.destination), false);
    assert.equal(readFileSync(join(f.source, ".next", "BUILD_ID"), "utf8"), "fixture-build\n");
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test("staging refuses a writable or linked destination parent", () => {
  const f = fixture();
  try {
    chmodSync(f.root, 0o775);
    assert.throws(() => stageNativeFrontend(f.source, f.destination, f.ids), /not group\/other writable/);
    assert.equal(existsSync(f.destination), false);
    chmodSync(f.root, 0o700);
    const linked = `${f.root}-link`;
    symlinkSync(f.root, linked);
    try {
      assert.throws(() => stageNativeFrontend(f.source, join(linked, "frontend"), f.ids), /must not be a symlink/);
    } finally { rmSync(linked); }
    assert.equal(existsSync(f.destination), false);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});
