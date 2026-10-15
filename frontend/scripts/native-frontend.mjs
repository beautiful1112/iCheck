import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { packageStandalone, publicApiBase } from "./native-package.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const [command, ...args] = process.argv.slice(2);
const [major, minor] = process.versions.node.split(".").map(Number);
if (major < 22 || (major === 22 && minor < 13)) throw new Error("Native frontend requires Node.js 22.13 or newer");
if (command === "build") {
  if (args.length) throw new Error("Native build does not accept extra arguments");
  const api = publicApiBase(process.env.NEXT_PUBLIC_ICHECK_API_URL);
  const result = spawnSync(process.execPath, [path.join(root, "node_modules", "next", "dist", "bin", "next"), "build", "--webpack"], {
    cwd: root, stdio: "inherit", env: { ...process.env, ICHECK_FRONTEND_TARGET: "native",
      NEXT_PUBLIC_ICHECK_API_URL: api, NEXT_TELEMETRY_DISABLED: "1" },
  });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
  const pkg = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));
  writeFileSync(path.join(root, ".next", "icheck-native-build.json"), JSON.stringify({
    format_version: "icheck.native-frontend/v1", version: pkg.version, api_base_url: api,
    build_id: readFileSync(path.join(root, ".next", "BUILD_ID"), "utf8").trim(),
    minimum_node_version: "22.13.0", framework: "next-standalone", framework_version: pkg.dependencies.next,
  }, null, 2) + "\n");
} else if (command === "package") {
  if (args.length !== 2 || args[0] !== "--out" || !args[1]) throw new Error("Usage: package:native -- --out NEW_DIRECTORY");
  console.log(JSON.stringify(packageStandalone(root, args[1])));
} else {
  throw new Error("Expected native build or package command");
}
