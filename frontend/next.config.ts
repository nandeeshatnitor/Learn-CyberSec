import type { NextConfig } from "next";

// Security headers (CSP, framing, nosniff...) are set per request in src/proxy.ts, because the
// terminal WebSocket origin comes from a runtime setting and must be part of the policy on every
// page. See the comment there.
const nextConfig: NextConfig = {
  output: "standalone",
  poweredByHeader: false,
  reactStrictMode: true,
};

export default nextConfig;
