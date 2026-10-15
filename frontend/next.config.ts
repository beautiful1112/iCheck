import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  ...(process.env.ICHECK_FRONTEND_TARGET === "native"
    ? { output: "standalone" as const, experimental: { cpus: 2 } }
    : {}),
};

export default nextConfig;
