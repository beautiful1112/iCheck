import { readFileSync } from "node:fs";

const release = JSON.parse(readFileSync(new URL("./native-release.json", import.meta.url), "utf8"));
if (release.format_version !== "icheck.native-frontend/v1") throw new Error("Invalid native frontend release");
const [major, minor] = process.versions.node.split(".").map(Number);
if (major < 22 || (major === 22 && minor < 13)) throw new Error("Node.js 22.13 or newer is required");
if (process.env.NEXT_PUBLIC_ICHECK_API_URL && process.env.NEXT_PUBLIC_ICHECK_API_URL !== release.api_base_url) {
  throw new Error("The browser API URL is baked into this package; rebuild to change it");
}
const host = process.env.ICHECK_FRONTEND_HOST || "127.0.0.1";
if (!["127.0.0.1", "::1"].includes(host)) throw new Error("Native frontend must bind loopback behind the trusted TLS ingress");
const port = process.env.ICHECK_FRONTEND_PORT || "3000";
if (!/^\d+$/.test(port) || Number(port) < 1 || Number(port) > 65535) throw new Error("Invalid frontend port");
process.env.HOSTNAME = host;
process.env.PORT = port;
process.env.NODE_ENV = "production";
process.env.ICHECK_FRONTEND_TARGET = "native";
process.env.NEXT_TELEMETRY_DISABLED = "1";
await import(new URL("./server.js", import.meta.url).href);
