import type { NextRequest } from "next/server";

import { adminSession } from "@/lib/admin-proxy";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  return adminSession(request, "GET");
}

export async function POST(request: NextRequest) {
  return adminSession(request, "POST");
}

export async function DELETE(request: NextRequest) {
  return adminSession(request, "DELETE");
}
