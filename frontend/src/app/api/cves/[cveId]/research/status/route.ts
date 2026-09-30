import type { NextRequest } from "next/server";

import { proxyResearch } from "@/lib/research-proxy";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest, { params }: { params: Promise<{ cveId: string }> }) {
  return proxyResearch(request, (await params).cveId, "status");
}
