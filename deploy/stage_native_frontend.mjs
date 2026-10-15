import { spawnSync } from "node:child_process";
import {
  chmodSync, closeSync, cpSync, existsSync, lchownSync, lstatSync, mkdirSync,
  openSync, readFileSync, readdirSync, readlinkSync, readSync, realpathSync,
  rmSync, statSync, chownSync,
} from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { auditStandalone, publicApiBase } from "../frontend/scripts/native-package.mjs";

const CACHE = join(".next", "cache");

function present(path) {
  try { lstatSync(path); return true; } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}

function within(root, child) {
  const tail = relative(root, child);
  return tail === "" || (tail !== ".." && !tail.startsWith(`..${sep}`) && !isAbsolute(tail));
}

function compareFiles(source, target) {
  const size = statSync(source).size;
  if (size !== statSync(target).size) throw new Error(`Staged file differs: ${source}`);
  const left = openSync(source, "r");
  let right;
  const a = Buffer.allocUnsafe(64 * 1024), b = Buffer.allocUnsafe(64 * 1024);
  try {
    right = openSync(target, "r");
    for (let offset = 0; offset < size; offset += a.length) {
      const length = Math.min(a.length, size - offset);
      if (readSync(left, a, 0, length, offset) !== length ||
          readSync(right, b, 0, length, offset) !== length ||
          !a.subarray(0, length).equals(b.subarray(0, length))) {
        throw new Error(`Staged file differs: ${source}`);
      }
    }
  } finally {
    closeSync(left);
    if (right !== undefined) closeSync(right);
  }
  return size;
}

function compareTrees(source, target) {
  const left = readdirSync(source).sort(), right = readdirSync(target).sort();
  if (left.length !== right.length || left.some((name, index) => name !== right[index])) {
    throw new Error(`Staged directory differs: ${source}`);
  }
  let files = 0, links = 0, bytes = 0;
  for (const name of left) {
    const a = join(source, name), b = join(target, name);
    const sourceInfo = lstatSync(a), targetInfo = lstatSync(b);
    if (sourceInfo.isDirectory() && targetInfo.isDirectory()) {
      const nested = compareTrees(a, b);
      files += nested.files; links += nested.links; bytes += nested.bytes;
    } else if (sourceInfo.isFile() && targetInfo.isFile()) {
      files += 1; bytes += compareFiles(a, b);
    } else if (sourceInfo.isSymbolicLink() && targetInfo.isSymbolicLink() && readlinkSync(a) === readlinkSync(b)) {
      links += 1;
    } else {
      throw new Error(`Staged entry type or link differs: ${a}`);
    }
  }
  return { files, links, bytes };
}

function harden(path, cache, packageUid, packageGid, serviceUid, serviceGid) {
  const info = lstatSync(path);
  if (info.isSymbolicLink()) {
    lchownSync(path, packageUid, packageGid);
  } else if (info.isDirectory()) {
    if (path === cache) {
      if (readdirSync(path).length) throw new Error("Native frontend cache must be empty at installation");
      chownSync(path, serviceUid, serviceGid);
      chmodSync(path, 0o700);
    } else {
      for (const name of readdirSync(path)) harden(join(path, name), cache,
        packageUid, packageGid, serviceUid, serviceGid);
      chownSync(path, packageUid, packageGid);
      chmodSync(path, 0o555);
    }
  } else if (info.isFile()) {
    chownSync(path, packageUid, packageGid);
    chmodSync(path, info.mode & 0o111 ? 0o555 : 0o444);
  } else {
    throw new Error("Native frontend contains a non-regular entry");
  }
}

function relaxDirectories(path) {
  const info = lstatSync(path);
  if (!info.isDirectory()) return;
  chmodSync(path, 0o700);
  for (const name of readdirSync(path)) relaxDirectories(join(path, name));
}

export function stageNativeFrontend(sourceArg, destinationArg, {
  serviceUid, serviceGid, packageUid = 0, packageGid = 0,
}) {
  if (!isAbsolute(sourceArg) || !isAbsolute(destinationArg)) {
    throw new Error("Native staging requires absolute source and destination paths");
  }
  for (const id of [serviceUid, serviceGid, packageUid, packageGid]) {
    if (!Number.isSafeInteger(id) || id < 0) throw new Error("Native staging requires valid numeric account IDs");
  }
  const source = realpathSync(sourceArg), destination = resolve(destinationArg);
  const parent = dirname(destination);
  if (realpathSync(parent) !== parent) throw new Error("Native destination parent must not be a symlink");
  const parentInfo = statSync(parent);
  if (parentInfo.uid !== packageUid || (parentInfo.mode & 0o022)) {
    throw new Error("Native destination parent must be owned by the package owner and not group/other writable");
  }
  if (within(source, destination) || within(destination, source)) {
    throw new Error("Native source and destination must be separate trees");
  }
  if (present(destination)) throw new Error("Native frontend destination already exists; refusing to overwrite it");
  const sourceEntries = auditStandalone(source);
  const manifest = JSON.parse(readFileSync(join(source, "native-release.json"), "utf8"));
  const buildId = readFileSync(join(source, ".next", "BUILD_ID"), "utf8").trim();
  if (manifest.format_version !== "icheck.native-frontend/v1" || !/^[A-Za-z0-9_-]{1,64}$/.test(buildId) ||
      buildId === "none" ||
      manifest.build_id !== buildId ||
      !Number.isSafeInteger(manifest.files) || sourceEntries !== manifest.files + 1 ||
      manifest.api_base_url !== publicApiBase(manifest.api_base_url) ||
      !lstatSync(join(source, CACHE)).isDirectory() || readdirSync(join(source, CACHE)).length ||
      !lstatSync(join(source, "start.mjs")).isFile()) {
    throw new Error("Native frontend source is incomplete or contains a used cache");
  }

  // Exclusive first-install claim. A service cannot read the 0700 tree until
  // comparison and ownership are complete; an existing deployment is untouched.
  mkdirSync(destination, { mode: 0o700 });
  try {
    for (const name of readdirSync(source)) {
      cpSync(join(source, name), join(destination, name), {
        recursive: true, dereference: false, verbatimSymlinks: true,
      });
    }
    auditStandalone(destination);
    const compared = compareTrees(source, destination);
    harden(destination, join(destination, CACHE), packageUid, packageGid, serviceUid, serviceGid);
    return { format_version: "icheck.native-frontend-stage/v1", destination,
      build_id: buildId, files_byte_compared: compared.files, links_compared: compared.links,
      bytes_compared: compared.bytes,
      cache_owner_uid: serviceUid, cache_owner_gid: serviceGid };
  } catch (error) {
    relaxDirectories(destination);
    rmSync(destination, { recursive: true, force: true });
    throw error;
  }
}

export function serviceIds() {
  const name = "icheck-frontend";
  const passwd = spawnSync("getent", ["passwd", name], { encoding: "utf8", timeout: 5_000 });
  const group = spawnSync("getent", ["group", name], { encoding: "utf8", timeout: 5_000 });
  if (passwd.status !== 0 || group.status !== 0) throw new Error("Dedicated frontend service account/group is missing");
  const userFields = passwd.stdout.trim().split(":"), groupFields = group.stdout.trim().split(":");
  const groups = spawnSync("id", ["-G", name], { encoding: "utf8", timeout: 5_000 });
  if (userFields[0] !== name || groupFields[0] !== name || userFields[3] !== groupFields[2] ||
      !/^[1-9][0-9]*$/.test(userFields[2]) || !/^[1-9][0-9]*$/.test(groupFields[2]) ||
      !["/usr/sbin/nologin", "/sbin/nologin"].includes(userFields[6]) ||
      groups.status !== 0 || groups.stdout.trim() !== groupFields[2]) {
    throw new Error("Frontend identity must be non-root, non-login and have only its own group");
  }
  return { serviceUid: Number(userFields[2]), serviceGid: Number(groupFields[2]) };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3) throw new Error("Usage: node deploy/stage_native_frontend.mjs ABSOLUTE_PACKAGE_DIR");
  if (process.getuid() !== 0) throw new Error("Native frontend installation requires the root deployment operator");
  const manifest = JSON.parse(readFileSync(join(process.argv[2], "native-release.json"), "utf8"));
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(manifest.build_id) || manifest.build_id === "none") {
    throw new Error("Native frontend build ID is not a safe release-directory name");
  }
  const result = stageNativeFrontend(process.argv[2],
    join("/opt/icheck/frontend-releases", manifest.build_id), serviceIds());
  process.stdout.write(JSON.stringify(result) + "\n");
}
