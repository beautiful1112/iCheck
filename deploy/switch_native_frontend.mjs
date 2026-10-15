import { spawnSync } from "node:child_process";
import {
  closeSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync,
  readlinkSync, realpathSync, readdirSync, renameSync, rmSync, statSync, symlinkSync,
  rmdirSync, chownSync, chmodSync,
} from "node:fs";
import { randomUUID } from "node:crypto";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { packagePermissions } from "./native_frontend_permissions.mjs";
import { serviceIds } from "./stage_native_frontend.mjs";

const BUILD_ID = /^[A-Za-z0-9_-]{1,64}$/;

function entry(path) {
  try { return lstatSync(path); } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

function syncDirectory(path) {
  const descriptor = openSync(path, "r");
  try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
}

function manifestBuild(path) {
  const manifest = JSON.parse(readFileSync(join(path, "native-release.json"), "utf8"));
  const build = readFileSync(join(path, ".next", "BUILD_ID"), "utf8").trim();
  if (manifest.format_version !== "icheck.native-frontend/v1" ||
      !BUILD_ID.test(build) || build === "none" || manifest.build_id !== build ||
      !statSync(join(path, "start.mjs")).isFile()) {
    throw new Error("Frontend release manifest, build ID or entry point is invalid");
  }
  return build;
}

export function readActiveFrontend(releaseRootArg, linkArg, packageUid = 0) {
  const releaseRoot = resolve(releaseRootArg), link = resolve(linkArg);
  const info = entry(link);
  if (!info) return null;
  if (!info.isSymbolicLink() || info.uid !== packageUid) {
    throw new Error("Active frontend path is not a package-owner symlink");
  }
  const target = readlinkSync(link);
  if (isAbsolute(target)) throw new Error("Active frontend link must be relative");
  const release = resolve(dirname(link), target);
  if (dirname(release) !== releaseRoot || !BUILD_ID.test(basename(release)) || basename(release) === "none" ||
      realpathSync(release) !== release || manifestBuild(release) !== basename(release)) {
    throw new Error("Active frontend link does not name a retained release");
  }
  return basename(release);
}

function resetCache(release) {
  const cache = join(release, ".next", "cache");
  for (const name of readdirSync(cache)) {
    // Cache is disposable after the service is stopped. rmSync unlinks links;
    // package code and immutable release history are never recursively removed.
    rmSync(join(cache, name), { recursive: true, force: true });
  }
  syncDirectory(cache);
}

export function switchNativeFrontend(releaseRootArg, linkArg, {
  toBuildId, expectedBuildId, serviceUid, serviceGid, packageUid = 0,
  ancestorFloor = "/", assertStopped, rebindCache = false,
  previousServiceUid, previousServiceGid,
}) {
  if (!isAbsolute(releaseRootArg) || !isAbsolute(linkArg) ||
      !BUILD_ID.test(toBuildId) || toBuildId === "none" ||
      (expectedBuildId !== "none" && !BUILD_ID.test(expectedBuildId)) ||
      typeof assertStopped !== "function") {
    throw new Error("Frontend cutover requires absolute paths, exact build IDs and a service-stop guard");
  }
  if (rebindCache && (![previousServiceUid, previousServiceGid, serviceUid, serviceGid]
      .every((id) => Number.isSafeInteger(id) && id >= 0))) {
    throw new Error("Cache identity migration requires exact previous and new numeric IDs");
  }
  const releaseRoot = resolve(releaseRootArg), link = resolve(linkArg);
  const parent = dirname(link);
  if (realpathSync(releaseRoot) !== releaseRoot || realpathSync(parent) !== parent ||
      dirname(releaseRoot) !== parent || basename(link) !== "frontend") {
    throw new Error("Frontend cutover requires the fixed sibling release and active paths");
  }
  for (const path of [releaseRoot, parent]) {
    const info = statSync(path);
    if (info.uid !== packageUid || (info.mode & 0o022)) {
      throw new Error("Frontend release and active parents must be package-owned and not group/other writable");
    }
  }
  const lock = join(releaseRoot, ".switch-lock");
  if (entry(lock)) throw new Error("Frontend switch lock exists; inspect the previous cutover before retrying");
  mkdirSync(lock, { mode: 0o700 });
  let temporary = null, swapped = false;
  try {
    const previous = readActiveFrontend(releaseRoot, link, packageUid);
    if ((previous || "none") !== expectedBuildId) {
      throw new Error("Active frontend build changed; expected-build comparison refused the cutover");
    }
    const release = join(releaseRoot, toBuildId);
    const info = entry(release);
    if (!info?.isDirectory() || realpathSync(release) !== release || manifestBuild(release) !== toBuildId ||
        !packagePermissions(release, {
          serviceUid: rebindCache ? previousServiceUid : serviceUid,
          serviceGid: rebindCache ? previousServiceGid : serviceGid, packageUid, ancestorFloor,
        })) {
      throw new Error("Target frontend release is missing, modified or has unsafe permissions");
    }
    if (assertStopped() !== true) throw new Error("Frontend service is not confirmed stopped");
    if (rebindCache) {
      if ((readActiveFrontend(releaseRoot, link, packageUid) || "none") !== expectedBuildId ||
          assertStopped() !== true) throw new Error("Frontend state changed before cache migration");
      resetCache(release);
      const cache = join(release, ".next", "cache");
      chownSync(cache, serviceUid, serviceGid);
      chmodSync(cache, 0o700);
      if (!packagePermissions(release, { serviceUid, serviceGid, packageUid, ancestorFloor })) {
        throw new Error("Cache migration failed final permissions verification; inspect before retrying");
      }
      return { format_version: "icheck.native-frontend-cache-identity/v1",
        previous, current: previous, changed: false, cache_build_id: toBuildId,
        previous_uid: previousServiceUid, previous_gid: previousServiceGid,
        service_uid: serviceUid, service_gid: serviceGid, cache_identity_rebound: true };
    }
    if (previous === toBuildId) {
      return { format_version: "icheck.native-frontend-switch/v1", previous, current: toBuildId, changed: false };
    }
    resetCache(release);
    temporary = join(parent, `.frontend-next-${randomUUID()}`);
    symlinkSync(relative(parent, release), temporary);
    syncDirectory(parent);
    // The parent is package-owner-only writable, and the lock serializes this
    // tool's compare-and-swap. Neither the old nor new release tree is moved.
    if ((readActiveFrontend(releaseRoot, link, packageUid) || "none") !== expectedBuildId ||
        assertStopped() !== true) {
      throw new Error("Frontend state changed before pointer swap");
    }
    renameSync(temporary, link);
    swapped = true;
    temporary = null;
    syncDirectory(parent);
    return { format_version: "icheck.native-frontend-switch/v1",
      previous: previous || "none", current: toBuildId, changed: true };
  } catch (error) {
    if (swapped) {
      throw new Error("Frontend pointer may have switched; inspect active build before any retry", { cause: error });
    }
    throw error;
  } finally {
    if (temporary && entry(temporary)) rmSync(temporary);
    rmdirSync(lock);
  }
}

function stoppedUnit(expectedBuildId) {
  const result = spawnSync("systemctl", ["show", "icheck-frontend.service",
    "--property=LoadState,ActiveState,MainPID,ControlPID", "--no-pager"],
  { encoding: "utf8", timeout: 5_000 });
  if (result.status !== 0) return false;
  const state = Object.fromEntries(result.stdout.trim().split("\n")
    .map((line) => line.split(/=(.*)/s).slice(0, 2)));
  return (state.LoadState === "loaded" || (expectedBuildId === "none" && state.LoadState === "not-found")) &&
    ["inactive", "failed"].includes(state.ActiveState) && state.MainPID === "0" && state.ControlPID === "0";
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args.length === 9 && args[0] === "--rebind-cache" && args[2] === "--expect" &&
      args[4] === "--from-uid" && args[6] === "--from-gid" && args[8] === "--acknowledge-drained") {
    if (process.getuid() !== 0) throw new Error("Cache migration requires the root deployment operator");
    const result = switchNativeFrontend("/opt/icheck/frontend-releases", "/opt/icheck/frontend", {
      toBuildId: args[1], expectedBuildId: args[3], previousServiceUid: Number(args[5]),
      previousServiceGid: Number(args[7]), rebindCache: true, ...serviceIds(),
      assertStopped: () => stoppedUnit(args[3]),
    });
    process.stdout.write(JSON.stringify(result) + "\n");
  } else {
  if (args.length !== 5 || args[0] !== "--to" || args[2] !== "--expect" ||
      args[4] !== "--acknowledge-drained") {
    throw new Error("Usage: node deploy/switch_native_frontend.mjs --to BUILD --expect BUILD|none --acknowledge-drained");
  }
  if (process.getuid() !== 0) throw new Error("Frontend cutover requires the root deployment operator");
  const [toBuildId, expectedBuildId] = [args[1], args[3]];
  const result = switchNativeFrontend("/opt/icheck/frontend-releases", "/opt/icheck/frontend", {
    toBuildId, expectedBuildId, ...serviceIds(),
    assertStopped: () => stoppedUnit(expectedBuildId),
  });
  process.stdout.write(JSON.stringify(result) + "\n");
  }
}
