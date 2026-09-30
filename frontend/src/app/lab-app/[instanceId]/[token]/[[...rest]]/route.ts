import type { NextRequest } from "next/server";

import { proxyLabApp } from "@/lib/sandbox-proxy";

export const dynamic = "force-dynamic";

type Context = { params: Promise<{ instanceId: string; token: string }> };

export async function GET(request: NextRequest, { params }: Context) {
  const { instanceId, token } = await params;
  return proxyLabApp(request, instanceId, token, "GET");
}

export async function HEAD(request: NextRequest, { params }: Context) {
  const { instanceId, token } = await params;
  return proxyLabApp(request, instanceId, token, "HEAD");
}

export async function POST(request: NextRequest, { params }: Context) {
  const { instanceId, token } = await params;
  return proxyLabApp(request, instanceId, token, "POST");
}
