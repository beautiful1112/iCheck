import { cpSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";

export function publicApiBase(value = "/api/v1") {
  if (value === "/api/v1") return value;
  let url;
  try { url = new URL(value); } catch { throw new Error("Native API base must be /api/v1 or an HTTPS API URL"); }
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash ||
      !url.pathname.endsWith("/api/v1")) {
    throw new Error("Native API base requires HTTPS, /api/v1 and no embedded credentials/query/fragment");
  }
  return url.href.replace(/\/$/, "");
}

function within(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === "" || (!relative.startsWith(".." + path.sep) && relative !== ".." && !path.isAbsolute(relative));
}

export function auditStandalone(root) {
  root = realpathSync(root);
  const visited = new Set();
  function inspect(file) {
    const actual = realpathSync(file);
    if (!within(root, actual)) throw new Error("Standalone package has an escaping symlink");
    const name = path.basename(file);
    if (name === ".env" || name.startsWith(".env.")) throw new Error("Environment files must not ship in the frontend package");
    if (visited.has(actual)) return;
    visited.add(actual);
    const info = lstatSync(actual);
    if (info.isDirectory()) for (const child of readdirSync(actual)) inspect(path.join(actual, child));
    else if (!info.isFile()) throw new Error("Standalone package contains a non-regular file");
  }
  inspect(root);
  return visited.size;
}

export function packageStandalone(projectRoot, destination) {
  const source = path.join(projectRoot, ".next", "standalone");
  destination = path.resolve(destination);
  if (existsSync(destination)) throw new Error("Native package destination already exists; refusing to overwrite it");
  if (within(source, destination)) throw new Error("Native package destination cannot be inside its source");
  for (const file of ["server.js", "package.json", ".next/BUILD_ID"]) {
    if (!existsSync(path.join(source, file))) throw new Error("A complete native standalone build is required");
  }
  const manifest = JSON.parse(readFileSync(path.join(projectRoot, ".next", "icheck-native-build.json"), "utf8"));
  if (manifest.format_version !== "icheck.native-frontend/v1") throw new Error("Native build manifest is invalid");
  manifest.api_base_url = publicApiBase(manifest.api_base_url);
  const buildId = readFileSync(path.join(projectRoot, ".next", "BUILD_ID"), "utf8").trim();
  if (!buildId || manifest.build_id !== buildId ||
      readFileSync(path.join(source, ".next", "BUILD_ID"), "utf8").trim() !== buildId) {
    throw new Error("Native manifest, server and assets must belong to the same build");
  }
  auditStandalone(source);
  mkdirSync(path.dirname(destination), { recursive: true });
  // Atomically claim a fresh directory; never merge into concurrent/user data.
  mkdirSync(destination, { mode: 0o700 });
  try {
    cpSync(source, destination, { recursive: true, dereference: false, verbatimSymlinks: true });
    cpSync(path.join(projectRoot, ".next", "static"), path.join(destination, ".next", "static"), { recursive: true });
    if (existsSync(path.join(projectRoot, "public"))) cpSync(path.join(projectRoot, "public"), path.join(destination, "public"), { recursive: true });
    cpSync(path.join(projectRoot, "scripts", "native-server.mjs"), path.join(destination, "start.mjs"));
    mkdirSync(path.join(destination, ".next", "cache"), { recursive: true, mode: 0o700 });
    const files = auditStandalone(destination);
    writeFileSync(path.join(destination, "native-release.json"), JSON.stringify({ ...manifest, files }, null, 2) + "\n");
    return { destination, files, api_base_url: manifest.api_base_url };
  } catch (error) {
    rmSync(destination, { recursive: true, force: true });
    throw error;
  }
}
