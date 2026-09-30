import { NextResponse, type NextRequest } from "next/server";

/**
 * Next.js answers a dynamic route with malformed percent-encoding (e.g. /cves/%E0%A4%A) with a
 * bare 500 before any page code runs. Rewrite those requests to a segment that the page (or the
 * research route handlers) reject through their normal not-found path instead.
 */
export function proxy(request: NextRequest) {
  try {
    decodeURIComponent(request.nextUrl.pathname);
  } catch {
    const path = request.nextUrl.pathname;
    const target = path.startsWith("/api/learning")
      ? "/api/learning/invalid"
      : path.startsWith("/api/")
        ? "/api/cves/invalid/research/status"
        : path.startsWith("/learn/")
          ? "/learn/invalid"
          : "/cves/invalid";
    return NextResponse.rewrite(new URL(target, request.url));
  }
  return NextResponse.next();
}

export const config = { matcher: ["/cves/:path*", "/api/cves/:path*", "/api/learning/:path*", "/learn/:path*"] };
