import { NextResponse, type NextRequest } from "next/server";

/**
 * Next.js answers a dynamic route with malformed percent-encoding (e.g. /cves/%E0%A4%A) with a
 * bare 500 before any page code runs. Rewrite those requests to a segment that the page rejects
 * through its normal not-found path instead.
 */
export function proxy(request: NextRequest) {
  try {
    decodeURIComponent(request.nextUrl.pathname);
  } catch {
    return NextResponse.rewrite(new URL("/cves/invalid", request.url));
  }
  return NextResponse.next();
}

export const config = { matcher: "/cves/:path*" };
