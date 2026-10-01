import "server-only";

import { NextResponse, type NextRequest } from "next/server";

import {
  backendUrl,
  forwardedFor,
  isSameOrigin,
  NO_STORE,
  problem,
  REQUEST_TIMEOUT_MS,
} from "@/lib/research-proxy";

/**
 * Same-origin proxy for the reviewer API (candidate labs).
 *
 * A reviewer signs in once by pasting their token; it is verified against the backend and kept in
 * an HttpOnly, SameSite=Strict cookie, so page script never sees it. This proxy turns the cookie
 * into the backend's `X-Admin-Token` header. Only a fixed set of method + path combinations is
 * forwarded, state-changing calls must come from this very site, request bodies are small JSON
 * objects, and upstream errors are reduced to their fixed code and message.
 */
export const ADMIN_COOKIE = "cvele_admin";
const SESSION_SECONDS = 60 * 60 * 8;
const PASS_THROUGH = new Set([200, 202, 401, 404, 409, 422, 429, 503]);
const MAX_BODY_BYTES = 20_000;
const TOKEN = /^[A-Za-z0-9_-]{20,128}$/;

const UUID = "[0-9a-fA-F-]{36}";
export type AdminRoute = { method: "GET" | "POST"; pattern: RegExp };
const ROUTES: AdminRoute[] = [
  { method: "GET", pattern: /^whoami$/ },
  { method: "GET", pattern: /^candidates$/ },
  { method: "POST", pattern: /^candidates$/ },
  { method: "GET", pattern: new RegExp(`^candidates/${UUID}$`) },
  {
    method: "POST",
    pattern: new RegExp(
      `^candidates/${UUID}/(approve|reject|request-changes|regenerate|rebuild|release)$`,
    ),
  },
  { method: "GET", pattern: /^versions$/ },
  { method: "POST", pattern: new RegExp(`^versions/${UUID}/withdraw$`) },
];

const STATUSES = new Set([
  "generating",
  "generation_failed",
  "spec_only",
  "building",
  "build_failed",
  "validating",
  "validation_failed",
  "awaiting_review",
  "changes_requested",
  "rejected",
  "approved",
]);

/** Only these query parameters are forwarded, and only with a recognisable value. */
function listQuery(request: NextRequest): string {
  const out = new URLSearchParams();
  const status = request.nextUrl.searchParams.get("status");
  if (status && STATUSES.has(status)) out.set("status", status);
  const cve = request.nextUrl.searchParams.get("cve_id");
  if (cve && /^CVE-[0-9]{4}-[0-9]{4,19}$/i.test(cve)) out.set("cve_id", cve);
  const family = request.nextUrl.searchParams.get("family");
  if (family && /^[a-z0-9-]{1,48}$/.test(family)) out.set("family", family);
  const text = out.toString();
  return text ? `?${text}` : "";
}

function cookieOptions(request: NextRequest) {
  const https =
    request.nextUrl.protocol === "https:" || request.headers.get("x-forwarded-proto") === "https";
  return {
    httpOnly: true,
    sameSite: "strict" as const,
    secure: https,
    path: "/",
    maxAge: SESSION_SECONDS,
  };
}

async function readBody(request: NextRequest): Promise<string | null> {
  const text = await request.text();
  if (!text) return "{}";
  if (text.length > MAX_BODY_BYTES) return null;
  try {
    const parsed: unknown = JSON.parse(text);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
    return JSON.stringify(parsed);
  } catch {
    return null;
  }
}

async function callBackend(
  path: string,
  token: string,
  method: "GET" | "POST",
  body?: string,
): Promise<NextResponse> {
  const init: RequestInit = {
    method,
    cache: "no-store",
    headers: {
      Accept: "application/json",
      "X-Admin-Token": token,
      ...(await forwardedFor()),
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
    },
    body,
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  };
  let upstream: Response;
  try {
    upstream = await fetch(`${backendUrl()}/api/admin/labs${path}`, init);
  } catch {
    return problem(503, "unavailable", "The API could not be reached.");
  }
  if (!PASS_THROUGH.has(upstream.status)) {
    return problem(503, "unavailable", "The API is not available right now.");
  }
  let json: unknown;
  try {
    json = await upstream.json();
  } catch {
    return problem(503, "unavailable", "The API returned an unreadable response.");
  }
  if (typeof json !== "object" || json === null || Array.isArray(json)) {
    return problem(503, "unavailable", "The API returned an unexpected response.");
  }
  if (upstream.status >= 400) {
    const error = (json as { error?: { code?: unknown; message?: unknown } }).error;
    const code = typeof error?.code === "string" ? error.code.slice(0, 40) : "error";
    const message =
      typeof error?.message === "string" ? error.message.slice(0, 400) : "Request failed.";
    const retry = upstream.headers.get("retry-after");
    return problem(
      upstream.status,
      code,
      message,
      retry && /^\d{1,6}$/.test(retry) ? { "Retry-After": retry } : {},
    );
  }
  return NextResponse.json(json, {
    status: upstream.status,
    headers: NO_STORE,
  });
}

export async function proxyAdmin(
  request: NextRequest,
  segments: string[] | undefined,
  method: "GET" | "POST",
): Promise<NextResponse> {
  const path = (segments ?? []).join("/");
  const allowed = ROUTES.some((r) => r.method === method && r.pattern.test(path));
  if (!allowed || (segments ?? []).some((s) => s.length > 60)) {
    return problem(404, "not_found", "Not found.");
  }
  if (method === "POST" && !isSameOrigin(request)) {
    return problem(403, "forbidden", "Cross-site requests are not allowed.");
  }
  const token = request.cookies.get(ADMIN_COOKIE)?.value;
  if (!token || !TOKEN.test(token)) return problem(401, "unauthorized", "Please sign in.");

  let body: string | undefined;
  if (method === "POST") {
    const read = await readBody(request);
    if (read === null) return problem(422, "validation_error", "The request body was rejected.");
    body = read;
  }
  const query = method === "GET" ? listQuery(request) : "";
  const response = await callBackend(`/${path}${query}`, token, method, body);
  // A token the backend no longer accepts is dropped, so the page returns to the sign-in form.
  if (response.status === 401)
    response.cookies.set(ADMIN_COOKIE, "", {
      ...cookieOptions(request),
      maxAge: 0,
    });
  return response;
}

/** POST {token} signs in (the token is verified, then stored); DELETE signs out; GET checks. */
export async function adminSession(
  request: NextRequest,
  method: "GET" | "POST" | "DELETE",
): Promise<NextResponse> {
  if (method !== "GET" && !isSameOrigin(request)) {
    return problem(403, "forbidden", "Cross-site requests are not allowed.");
  }
  if (method === "DELETE") {
    const response = NextResponse.json({ ok: true }, { headers: NO_STORE });
    response.cookies.set(ADMIN_COOKIE, "", {
      ...cookieOptions(request),
      maxAge: 0,
    });
    return response;
  }
  let token = request.cookies.get(ADMIN_COOKIE)?.value;
  if (method === "POST") {
    const body = await readBody(request);
    let candidate: unknown;
    try {
      candidate = body ? (JSON.parse(body) as { token?: unknown }).token : undefined;
    } catch {
      candidate = undefined;
    }
    if (typeof candidate !== "string" || !TOKEN.test(candidate.trim())) {
      return problem(401, "unauthorized", "That is not a valid reviewer token.");
    }
    token = candidate.trim();
  }
  if (!token || !TOKEN.test(token)) return problem(401, "unauthorized", "Please sign in.");
  const result = await callBackend("/whoami", token, "GET");
  if (result.status === 200 && method === "POST") {
    result.cookies.set(ADMIN_COOKIE, token, cookieOptions(request));
  }
  if (result.status === 401 && method === "GET") {
    result.cookies.set(ADMIN_COOKIE, "", {
      ...cookieOptions(request),
      maxAge: 0,
    });
  }
  return result;
}
