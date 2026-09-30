import { NextResponse, type NextRequest } from "next/server";

import { contentSecurityPolicy, SECURITY_HEADERS, terminalOrigin } from "@/lib/csp";

/**
 * Two jobs:
 *
 * 1. Next.js answers a dynamic route with malformed percent-encoding (e.g. /cves/%E0%A4%A) with a
 *    bare 500 before any page code runs. Rewrite those requests to a segment that the page (or the
 *    research route handlers) reject through their normal not-found path instead.
 * 2. Give every page its security headers (CSP, framing, nosniff...). They are set here, at
 *    runtime, rather than in next.config.ts because the lab workspace opens a WebSocket to the
 *    terminal gateway and its `connect-src` must name that origin, which comes from the runtime
 *    TERMINAL_WS_ORIGIN setting (never from the request). It has to be the same policy on every
 *    page: a client-side navigation from a lesson to a lab keeps the *first* page's policy, so a
 *    lab-only policy would silently block the terminal for anyone who arrived by clicking.
 *
 *    The lab's own app (/lab-app/*) is deliberately excluded: it is untrusted content and carries
 *    its own sandboxing headers from the backend.
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
  if (!path.startsWith("/api/") && !path.startsWith("/lab-app/")) {
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
    "/api/cves/:path*",
    "/api/learning/:path*",
    "/api/sandbox/:path*",
    "/lab-app/:path*",
    // every page (not Next's own assets, the API handlers or the icon)
    "/((?!api/|_next/|icon.svg|favicon.ico).*)",
  ],
};
