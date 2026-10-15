import test from "node:test";
import assert from "node:assert/strict";
import {
  chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync,
  readlinkSync, readdirSync, rmSync, symlinkSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { stageNativeFrontend } from "../stage_native_frontend.mjs";
import { readActiveFrontend, switchNativeFrontend } from "../switch_native_frontend.mjs";

function source(root, build) {
  const path = join(root, `source-${build}`);
  mkdirSync(join(path, ".next", "cache"), { recursive: true });
  mkdirSync(join(path, "public"));
  writeFileSync(join(path, "native-release.json"), JSON.stringify({
    format_version: "icheck.native-frontend/v1", build_id: build,
    api_base_url: "/api/v1", files: 7,
  }));
  writeFileSync(join(path, ".next", "BUILD_ID"), build);
  writeFileSync(join(path, "start.mjs"), "export const ready = true;\n");
  writeFileSync(join(path, "public", "favicon.svg"), `<svg id="${build}"/>`);
  return path;
}

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "icheck-native-switch-"));
  chmodSync(root, 0o755);
  const releases = join(root, "frontend-releases"), active = join(root, "frontend");
  mkdirSync(releases, { mode: 0o755 });
  const options = {
    packageUid: process.getuid(), packageGid: process.getgid(),
    serviceUid: process.getuid(), serviceGid: process.getgid(),
    ancestorFloor: root, assertStopped: () => true,
  };
  for (const build of ["build-one", "build-two"]) {
    stageNativeFrontend(source(root, build), join(releases, build), options);
  }
  return { root, releases, active, options };
}

function cleanup(path) {
  function relax(directory) {
    if (!lstatSync(directory).isDirectory()) return;
    chmodSync(directory, 0o700);
    for (const name of readdirSync(directory)) relax(join(directory, name));
  }
  relax(path);
  rmSync(path, { recursive: true, force: true });
}

test("atomic pointer promotion retains both releases and supports exact rollback", () => {
  const f = fixture();
  try {
    const first = switchNativeFrontend(f.releases, f.active, {
      ...f.options, toBuildId: "build-one", expectedBuildId: "none",
    });
    assert.deepEqual([first.previous, first.current, first.changed], ["none", "build-one", true]);
    assert.equal(readActiveFrontend(f.releases, f.active, f.options.packageUid), "build-one");
    assert.equal(readlinkSync(f.active), "frontend-releases/build-one");
    const second = switchNativeFrontend(f.releases, f.active, {
      ...f.options, toBuildId: "build-two", expectedBuildId: "build-one",
    });
    assert.deepEqual([second.previous, second.current, second.changed], ["build-one", "build-two", true]);
    const oldCache = join(f.releases, "build-one", ".next", "cache");
    const sentinel = join(f.root, "external-sentinel");
    writeFileSync(sentinel, "untouched");
    symlinkSync(sentinel, join(oldCache, "untrusted-link"));
    writeFileSync(join(oldCache, "generated-data"), "discard on rollback");
    const rollback = switchNativeFrontend(f.releases, f.active, {
      ...f.options, toBuildId: "build-one", expectedBuildId: "build-two",
    });
    assert.deepEqual([rollback.previous, rollback.current, rollback.changed], ["build-two", "build-one", true]);
    assert.equal(readFileSync(sentinel, "utf8"), "untouched");
    assert.equal(existsSync(join(oldCache, "generated-data")), false);
    assert.equal(readActiveFrontend(f.releases, f.active, f.options.packageUid), "build-one");
    assert.equal(readFileSync(join(f.releases, "build-two", ".next", "BUILD_ID"), "utf8"), "build-two");
  } finally { cleanup(f.root); }
});

test("stale expected build and a live-service guard leave active pointer unchanged", () => {
  const f = fixture();
  try {
    switchNativeFrontend(f.releases, f.active, {
      ...f.options, toBuildId: "build-one", expectedBuildId: "none",
    });
    assert.throws(() => switchNativeFrontend(f.releases, f.active, {
      ...f.options, toBuildId: "build-two", expectedBuildId: "none",
    }), /expected-build comparison/);
    assert.throws(() => switchNativeFrontend(f.releases, f.active, {
      ...f.options, toBuildId: "build-two", expectedBuildId: "build-one",
      assertStopped: () => false,
    }), /not confirmed stopped/);
    assert.equal(readActiveFrontend(f.releases, f.active, f.options.packageUid), "build-one");
    assert.equal(existsSync(join(f.releases, ".switch-lock")), false);
    const same = switchNativeFrontend(f.releases, f.active, {
      ...f.options, toBuildId: "build-one", expectedBuildId: "build-one",
    });
    assert.equal(same.changed, false);
  } finally { cleanup(f.root); }
});

test("invalid pointers, missing releases and a retained lock fail closed", () => {
  const f = fixture();
  try {
    assert.throws(() => switchNativeFrontend(f.releases, f.active, {
      ...f.options, toBuildId: "../escape", expectedBuildId: "none",
    }), /exact build IDs/);
    assert.throws(() => switchNativeFrontend(f.releases, f.active, {
      ...f.options, toBuildId: "not-staged", expectedBuildId: "none",
    }), /missing, modified or has unsafe permissions/);
    mkdirSync(join(f.releases, ".switch-lock"));
    assert.throws(() => switchNativeFrontend(f.releases, f.active, {
      ...f.options, toBuildId: "build-one", expectedBuildId: "none",
    }), /lock exists/);
    rmSync(join(f.releases, ".switch-lock"), { recursive: true });
    mkdirSync(f.active);
    assert.throws(() => switchNativeFrontend(f.releases, f.active, {
      ...f.options, toBuildId: "build-one", expectedBuildId: "none",
    }), /not a package-owner symlink/);
    rmSync(f.active, { recursive: true });
    symlinkSync("/tmp/not-a-release", f.active);
    assert.throws(() => readActiveFrontend(f.releases, f.active, f.options.packageUid), /must be relative/);
  } finally { cleanup(f.root); }
});

test("cache identity rebind is stopped-only, exact-owner, and never swaps or alters code", () => {
  const f = fixture();
  try {
    switchNativeFrontend(f.releases, f.active, {
      ...f.options, toBuildId: "build-one", expectedBuildId: "none",
    });
    const cache = join(f.releases, "build-one", ".next", "cache");
    const code = join(f.releases, "build-one", "start.mjs");
    const before = readFileSync(code);
    writeFileSync(join(cache, "discardable"), "old cache");
    const sentinel = join(f.root, "sentinel");
    writeFileSync(sentinel, "retained");
    symlinkSync(sentinel, join(cache, "outside-link"));
    const options = {...f.options, toBuildId: "build-one", expectedBuildId: "build-one", rebindCache: true,
      previousServiceUid: f.options.serviceUid, previousServiceGid: f.options.serviceGid};
    assert.throws(() => switchNativeFrontend(f.releases, f.active, {
      ...options, assertStopped: () => false,
    }), /not confirmed stopped/);
    assert.equal(existsSync(join(cache, "discardable")), true);
    assert.throws(() => switchNativeFrontend(f.releases, f.active, {
      ...options, previousServiceUid: f.options.serviceUid + 1,
    }), /unsafe permissions/);
    const result = switchNativeFrontend(f.releases, f.active, options);
    assert.equal(result.cache_identity_rebound, true);
    assert.equal(result.changed, false);
    assert.equal(readlinkSync(f.active), "frontend-releases/build-one");
    assert.equal(existsSync(join(cache, "discardable")), false);
    assert.equal(readFileSync(sentinel, "utf8"), "retained");
    assert.deepEqual(readFileSync(code), before);
    assert.equal(lstatSync(code).mode & 0o777, 0o444);
  } finally { cleanup(f.root); }
});
