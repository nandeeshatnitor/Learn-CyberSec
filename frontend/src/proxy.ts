import { NextResponse, type NextRequest } from "next/server";

import { contentSecurityPolicy, SECURITY_HEADERS, terminalOrigin } from "@/lib/csp";

/**
 * Two jobs:
 *
 * 1. Next.js answers a dynamic route with malformed percent-encoding (e.g. /cves/%E0%A4%A) with a
 *    bare 500 before any page code runs. Rewrite those requests to a segment that the page (or the
 *    research route handlers) reject through their normal not-found path instead.
 * 2. Give the lab workspace (/lab/*) its security headers. It is the one page that opens a
 *    WebSocket to the terminal gateway, so its `connect-src` names that origin, read at runtime
 *    from TERMINAL_WS_ORIGIN (never from the request).
 */
export function proxy(request: NextRequest) {
  const path = request.nextUrl.pathname;
  try {
    decodeURIComponent(path);
  } catch {
    const target = path.startsWith("/api/learning")
      ? "/api/learning/invalid"
      : path.startsWith("/api/sandbox")
        ? "/api/sandbox/invalid"
        : path.startsWith("/api/")
          ? "/api/cves/invalid/research/status"
          : path.startsWith("/learn/")
            ? "/learn/invalid"
            : path.startsWith("/lab-app/")
              ? "/lab-app/invalid/invalid"
              : path.startsWith("/lab/")
                ? "/lab/invalid"
                : "/cves/invalid";
    return NextResponse.rewrite(new URL(target, request.url));
  }
  const response = NextResponse.next();
  if (path.startsWith("/lab/")) {
    const origin = terminalOrigin(process.env.TERMINAL_WS_ORIGIN);
    response.headers.set(
      "Content-Security-Policy",
      contentSecurityPolicy({
        dev: process.env.NODE_ENV !== "production",
        connect: origin ? [origin] : [],
      }),
    );
    for (const { key, value } of SECURITY_HEADERS) response.headers.set(key, value);
  }
  return response;
}

export const config = {
  matcher: [
    "/cves/:path*",
    "/api/cves/:path*",
    "/api/learning/:path*",
    "/api/sandbox/:path*",
    "/learn/:path*",
    "/lab/:path*",
    "/lab-app/:path*",
  ],
};
