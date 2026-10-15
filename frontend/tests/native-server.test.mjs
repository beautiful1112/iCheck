import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

function start(overrides = {}, manifest = { format_version: "icheck.native-frontend/v1", api_base_url: "/api/v1" }) {
  const root = mkdtempSync(path.join(tmpdir(), "icheck-native-server-"));
  try {
    cpSync(new URL("../scripts/native-server.mjs", import.meta.url), path.join(root, "start.mjs"));
    writeFileSync(path.join(root, "native-release.json"), JSON.stringify(manifest));
    writeFileSync(path.join(root, "server.js"),
      "console.log(JSON.stringify({host:process.env.HOSTNAME,port:process.env.PORT,mode:process.env.NODE_ENV,target:process.env.ICHECK_FRONTEND_TARGET}));\n");
    const env = { ...process.env };
    for (const key of ["ICHECK_FRONTEND_HOST", "ICHECK_FRONTEND_PORT", "NEXT_PUBLIC_ICHECK_API_URL", "NODE_OPTIONS", "NODE_PATH"]) delete env[key];
    return spawnSync(process.execPath, [path.join(root, "start.mjs")], {
      cwd: tmpdir(), env: { ...env, ...overrides }, encoding: "utf8", timeout: 10000,
    });
  } finally { rmSync(root, { recursive: true, force: true }); }
}

test("native runner overrides ambient machine hostname and starts production on loopback", () => {
  const result = start({ HOSTNAME: "public-machine", PORT: "8080", NODE_ENV: "development" });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), { host: "127.0.0.1", port: "3000", mode: "production", target: "native" });
  const custom = start({ ICHECK_FRONTEND_HOST: "::1", ICHECK_FRONTEND_PORT: "3407", NEXT_PUBLIC_ICHECK_API_URL: "/api/v1" });
  assert.equal(custom.status, 0, custom.stderr);
  assert.equal(JSON.parse(custom.stdout).port, "3407");
});

test("native runner refuses public binding, invalid ports and runtime API URL substitution", () => {
  for (const env of [
    { ICHECK_FRONTEND_HOST: "0.0.0.0" }, { ICHECK_FRONTEND_HOST: "monitor.example.test" },
    { ICHECK_FRONTEND_PORT: "0" }, { ICHECK_FRONTEND_PORT: "65536" }, { ICHECK_FRONTEND_PORT: "3e3" },
    { NEXT_PUBLIC_ICHECK_API_URL: "https://other.example.test/api/v1" },
  ]) {
    const result = start(env);
    assert.notEqual(result.status, 0);
    assert.equal(result.stdout, "", "invalid configuration must not invoke the server");
  }
});

test("native runner refuses an unknown release contract before invoking the server", () => {
  const result = start({}, { format_version: "unknown", api_base_url: "/api/v1" });
  assert.notEqual(result.status, 0);
  assert.equal(result.stdout, "");
});
