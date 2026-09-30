import type { NextRequest } from "next/server";

import { proxyResearch } from "@/lib/research-proxy";

export const dynamic = "force-dynamic";

type Context = { params: Promise<{ cveId: string }> };

/** Start (or join, or reuse) research for a CVE. */
export async function POST(request: NextRequest, { params }: Context) {
  return proxyResearch(request, (await params).cveId, "start");
}

/** The stored learning guide. */
export async function GET(request: NextRequest, { params }: Context) {
  return proxyResearch(request, (await params).cveId, "guide");
}
