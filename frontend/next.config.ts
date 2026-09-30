import type { NextConfig } from "next";

import { contentSecurityPolicy, SECURITY_HEADERS } from "./src/lib/csp";

const isDev = process.env.NODE_ENV !== "production";

// Baseline CSP. Next.js injects inline bootstrap scripts, so 'unsafe-inline' is needed for
// scripts until a nonce-based CSP is introduced. All other sources are locked to same-origin,
// and the browser never talks to the backend directly (only server components do).
//
// Two path groups get their headers elsewhere:
//  - /lab/*      the lab workspace also opens a WebSocket to the terminal gateway, so its CSP is
//                built per request in src/proxy.ts (from the runtime TERMINAL_WS_ORIGIN setting);
//  - /lab-app/*  the lab's own (untrusted, deliberately vulnerable) web app. Its headers come from
//                the backend: `Content-Security-Policy: sandbox`, frame-ancestors 'self', nosniff.
const nextConfig: NextConfig = {
  output: "standalone",
  poweredByHeader: false,
  reactStrictMode: true,
  async headers() {
    return [
      {
        source: "/((?!lab/|lab-app/).*)",
        headers: [
          { key: "Content-Security-Policy", value: contentSecurityPolicy({ dev: isDev }) },
          ...SECURITY_HEADERS,
        ],
      },
    ];
  },
};

export default nextConfig;
