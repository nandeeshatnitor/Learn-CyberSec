import "server-only";

import { headers } from "next/headers";
import { NextResponse, type NextRequest } from "next/server";

import { parseCveIdParam } from "@/lib/cve";

/**
 * Same-origin proxy from the browser to the backend's research endpoints.
 *
 * The browser never learns the backend URL and never talks to it. This module forwards only what
 * the backend needs (a sanitised X-Forwarded-For for per-visitor rate limiting; no cookies, no
 * Authorization, nothing else), lets only a fixed set of status codes through, and always answers
 * with a small JSON body of a known shape, so upstream error text can never reach a visitor.
 */
export const REQUEST_TIMEOUT_MS = 30_000;
const PASS_THROUGH = new Set([200, 202, 404, 422, 429, 503]);
export const NO_STORE = { "Cache-Control": "no-store" };

export type ResearchAction = "start" | "status" | "guide";

export function backendUrl(): string {
  return (process.env.BACKEND_URL ?? "http://localhost:8000").replace(/\/+$/, "");
}

export function problem(status: number, code: string, message: string, extra: HeadersInit = {}) {
  return NextResponse.json({ error: { code, message } }, { status, headers: { ...NO_STORE, ...extra } });
}

export async function forwardedFor(): Promise<Record<string, string>> {
  const value = (await headers()).get("x-forwarded-for");
  return value && /^[0-9a-fA-F.:,\s]{1,200}$/.test(value) ? { "X-Forwarded-For": value } : {};
}

/**
 * Browsers attach Sec-Fetch-Site (and Origin) to every request; a state-changing call is accepted
 * only when the browser says it came from this very site. Requests without either are refused.
 */
export function isSameOrigin(request: NextRequest): boolean {
  const site = request.headers.get("sec-fetch-site");
  if (site) return site === "same-origin";
  const origin = request.headers.get("origin");
  const host = request.headers.get("host");
  if (!origin || !host) return false;
  try {
    return new URL(origin).host === host;
  } catch {
    return false;
  }
}

async function readRefresh(request: NextRequest): Promise<boolean> {
  try {
    const body: unknown = await request.json();
    return typeof body === "object" && body !== null && (body as { refresh?: unknown }).refresh === true;
  } catch {
    return false;
  }
}

export async function proxyResearch(
  request: NextRequest,
  rawCveId: string,
  action: ResearchAction,
): Promise<NextResponse> {
  const cveId = parseCveIdParam(rawCveId);
  if (!cveId) return problem(404, "not_found", "Not found.");

  const init: RequestInit = {
    cache: "no-store",
    headers: { Accept: "application/json", ...(await forwardedFor()) },
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  };
  let path = `/api/cves/${encodeURIComponent(cveId)}/research`;
  if (action === "status") path += "/status";
  if (action === "start") {
    if (!isSameOrigin(request)) return problem(403, "forbidden", "Cross-site requests are not allowed.");
    init.method = "POST";
    init.headers = { ...init.headers, "Content-Type": "application/json" };
    init.body = JSON.stringify({ refresh: await readRefresh(request) });
  }

  let response: Response;
  try {
    response = await fetch(`${backendUrl()}${path}`, init);
  } catch {
    return problem(503, "unavailable", "The API could not be reached.");
  }
  if (!PASS_THROUGH.has(response.status)) {
    return problem(503, "unavailable", "The API is not available right now.");
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    return problem(503, "unavailable", "The API returned an unreadable response.");
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return problem(503, "unavailable", "The API returned an unexpected response.");
  }

  if (response.status >= 400) {
    // Keep only the fixed code and message the backend defines; drop details and anything else.
    const error = (body as { error?: { code?: unknown; message?: unknown } }).error;
    const code = typeof error?.code === "string" ? error.code.slice(0, 40) : "error";
    const message = typeof error?.message === "string" ? error.message.slice(0, 300) : "Request failed.";
    const retry = response.headers.get("retry-after");
    return problem(response.status, code, message, retry && /^\d{1,6}$/.test(retry) ? { "Retry-After": retry } : {});
  }
  return NextResponse.json(body, { status: response.status, headers: NO_STORE });
}
