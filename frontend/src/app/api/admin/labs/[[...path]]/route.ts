import type { NextRequest } from "next/server";

import { proxyAdmin } from "@/lib/admin-proxy";

export const dynamic = "force-dynamic";

type Context = { params: Promise<{ path?: string[] }> };

export async function GET(request: NextRequest, { params }: Context) {
  return proxyAdmin(request, (await params).path, "GET");
}

export async function POST(request: NextRequest, { params }: Context) {
  return proxyAdmin(request, (await params).path, "POST");
}
