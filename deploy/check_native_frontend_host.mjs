import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, realpathSync } from "node:fs";
import { resolve } from "node:path";
import { packagePermissions } from "./native_frontend_permissions.mjs";
import { readActiveFrontend } from "./switch_native_frontend.mjs";

const [candidateArg, unitArg] = process.argv.slice(2);
if (!candidateArg || !unitArg || process.argv.length !== 4) {
  throw new Error("Usage: node deploy/check_native_frontend_host.mjs CANDIDATE_FRONTEND UNIT_FILE");
}

const candidate = resolve(candidateArg);
const unit = readFileSync(resolve(unitArg), "utf8");
const field = (name) => unit.match(new RegExp(`^${name}=(.+)$`, "m"))?.[1]?.trim() || null;
const execStart = field("ExecStart")?.split(/\s+/) || [];
const nodePath = execStart[0] || null;
const installedPackage = field("WorkingDirectory");
const account = field("User");
const group = field("Group");
const failures = [];

let buildId = null;
try {
  const manifest = JSON.parse(readFileSync(`${candidate}/native-release.json`, "utf8"));
  buildId = readFileSync(`${candidate}/.next/BUILD_ID`, "utf8").trim();
  if (manifest.format_version !== "icheck.native-frontend/v1" || manifest.build_id !== buildId) {
    failures.push("candidate package build ID does not match its manifest");
  }
} catch {
  failures.push("candidate package is missing or unreadable");
}

const systemd = spawnSync("systemctl", [
  "show", "icheck-frontend.service", "--property=FragmentPath,DropInPaths,LoadState,ActiveState", "--no-pager",
], { encoding: "utf8", timeout: 5_000 });
const installedUnit = systemd.status === 0
  ? Object.fromEntries(systemd.stdout.trim().split("\n").map((line) => line.split(/=(.*)/s).slice(0, 2)))
  : {};
const suppliedUnitIsLoaded = Boolean(installedUnit.FragmentPath && existsSync(installedUnit.FragmentPath) &&
  realpathSync(resolve(unitArg)) === realpathSync(installedUnit.FragmentPath));
if (installedUnit.LoadState !== "loaded" || !installedUnit.FragmentPath) {
  failures.push("icheck-frontend.service is not installed as a loaded systemd unit");
} else if (!suppliedUnitIsLoaded) {
  failures.push("supplied unit file is not the loaded systemd unit fragment");
}
if (installedUnit.DropInPaths) {
  failures.push("loaded unit has drop-ins that this fragment-only preflight cannot evaluate");
}
if (installedUnit.ActiveState && !["active", "inactive"].includes(installedUnit.ActiveState)) {
  failures.push("frontend unit is failed or transitioning; inspect its service state before proceeding");
}

let nodeVersion = null;
if (!nodePath?.startsWith("/") || !existsSync(nodePath)) {
  failures.push("unit ExecStart does not name an installed absolute Node executable");
} else {
  const result = spawnSync(nodePath, ["--version"], { encoding: "utf8", timeout: 5_000 });
  const version = result.status === 0 ? /^v?(\d+)\.(\d+)\.(\d+)/.exec(result.stdout.trim()) : null;
  if (version) {
    nodeVersion = result.stdout.trim();
    if (Number(version[1]) < 22 || (Number(version[1]) === 22 && Number(version[2]) < 13)) {
      failures.push(`unit Node ${nodeVersion} is below required 22.13.0`);
    }
  } else {
    failures.push("unit Node executable did not report a usable version");
  }
}

if (!installedPackage?.startsWith("/") || execStart[1] !== `${installedPackage}/start.mjs`) {
  failures.push("unit WorkingDirectory and start.mjs path disagree");
}
if (field("ProtectSystem") !== "strict" ||
    field("ReadWritePaths") !== "/opt/icheck/frontend/.next/cache") {
  failures.push("unit must retain strict filesystem protection with only the active cache writable");
}
if (field("SuccessExitStatus") !== "143") {
  failures.push("unit must recognize the Next.js graceful SIGTERM exit status 143");
}
if (account !== "icheck-frontend" || group !== "icheck-frontend") {
  failures.push("unit does not select the isolated frontend service account");
}
const serviceAccount = spawnSync("getent", ["passwd", "icheck-frontend"], { encoding: "utf8", timeout: 5_000 });
const serviceGroup = spawnSync("getent", ["group", "icheck-frontend"], { encoding: "utf8", timeout: 5_000 });
const serviceGroups = spawnSync("id", ["-G", "icheck-frontend"], { encoding: "utf8", timeout: 5_000 });
const userFields = serviceAccount.stdout?.trim().split(":") || [];
const groupFields = serviceGroup.stdout?.trim().split(":") || [];
const accountExists = serviceAccount.status === 0 && userFields[0] === "icheck-frontend" &&
  serviceGroup.status === 0 && groupFields[0] === "icheck-frontend" &&
  /^[1-9][0-9]*$/.test(userFields[2]) && /^[1-9][0-9]*$/.test(groupFields[2]) &&
  userFields[3] === groupFields[2] && ["/usr/sbin/nologin", "/sbin/nologin"].includes(userFields[6]) &&
  serviceGroups.status === 0 && serviceGroups.stdout.trim() === groupFields[2];
if (!accountExists) {
  failures.push("isolated non-root frontend identity is absent or has unsafe group/login settings");
}
let installedBuildId = null;
let activeReleaseBuildId = null;
let stagedBuildValid = false;
let staticPermissionsValid = false;
if (!installedPackage || !existsSync(installedPackage)) {
  failures.push("frontend is not staged at the unit WorkingDirectory");
} else {
  try {
    activeReleaseBuildId = readActiveFrontend("/opt/icheck/frontend-releases", installedPackage);
  } catch {
    failures.push("active frontend pointer is not a valid root-owned retained-release link");
  }
  try {
    const manifest = JSON.parse(readFileSync(`${installedPackage}/native-release.json`, "utf8"));
    installedBuildId = readFileSync(`${installedPackage}/.next/BUILD_ID`, "utf8").trim();
    stagedBuildValid = manifest.format_version === "icheck.native-frontend/v1" &&
      manifest.build_id === installedBuildId && installedBuildId === buildId &&
      activeReleaseBuildId === installedBuildId &&
      existsSync(`${installedPackage}/start.mjs`);
    if (!stagedBuildValid) {
      failures.push("staged frontend does not match the candidate build");
    }
  } catch {
    failures.push("staged frontend manifest or entry point is missing or unreadable");
  }
  try {
    const user = Number(serviceAccount.stdout.trim().split(":")[2]);
    const groupId = Number(serviceGroup.stdout.trim().split(":")[2]);
    staticPermissionsValid = accountExists && activeReleaseBuildId !== null &&
      packagePermissions(realpathSync(installedPackage), {
      serviceUid: user, serviceGid: groupId,
    });
  } catch {
    staticPermissionsValid = false;
  }
  if (!staticPermissionsValid) {
    failures.push("installed frontend ownership, read-only files or service cache permissions are invalid");
  }
}

const result = {
  format_version: "icheck.native-frontend-host-preflight/v1",
  candidate_build_id: buildId,
  unit_node_path: nodePath,
  unit_node_version: nodeVersion,
  installed_unit_load_state: installedUnit.LoadState || null,
  installed_unit_fragment: installedUnit.FragmentPath || null,
  installed_unit_drop_in_paths: installedUnit.DropInPaths || null,
  installed_unit_active_state: installedUnit.ActiveState || null,
  supplied_unit_is_loaded_fragment: suppliedUnitIsLoaded,
  unit_working_directory: installedPackage,
  dedicated_service_account: account === "icheck-frontend" && group === "icheck-frontend",
  service_account_exists: accountExists,
  staged_build_id: installedBuildId,
  active_release_build_id: activeReleaseBuildId,
  staged_build_matches_candidate: stagedBuildValid,
  static_package_permissions_valid: staticPermissionsValid,
  failures,
  passed: failures.length === 0,
};
process.stdout.write(JSON.stringify(result) + "\n");
if (!result.passed) process.exitCode = 1;
