import "server-only";

import { randomBytes } from "node:crypto";
import { NextResponse, type NextRequest } from "next/server";

import { normalizeCveId } from "@/lib/cve";
import {
  backendUrl,
  forwardedFor,
  isSameOrigin,
  NO_STORE,
  problem,
  REQUEST_TIMEOUT_MS,
} from "@/lib/research-proxy";

/**
 * Same-origin proxy for the learning-session API.
 *
 * Identity: an anonymous learner is a random token in an HttpOnly cookie. This proxy creates it on
 * first use, keeps it out of JavaScript's reach, and forwards it to the backend in a header (the
 * backend stores only a hash). Nothing else from the visitor is forwarded except a sanitised
 * X-Forwarded-For. Only a fixed set of paths and methods is allowed, and upstream errors are reduced
 * to their fixed code and message.
 */
export const LEARNER_COOKIE = "cvele_learner";
const LEARNING_PASS_THROUGH = new Set([200, 401, 404, 409, 422, 429, 503]);
const MAX_BODY_BYTES = 20_000;

const UUID = "[0-9a-fA-F-]{36}";
const TASK = "t[0-9]{1,2}";
export type LearnerRoute = { method: "GET" | "POST"; pattern: RegExp };
const ROUTES: LearnerRoute[] = [
  { method: "POST", pattern: /^$/ },
  { method: "GET", pattern: /^by-cve\/(CVE-[0-9]{4}-[0-9]{4,19})$/ },
  { method: "GET", pattern: new RegExp(`^${UUID}$`) },
  { method: "POST", pattern: new RegExp(`^${UUID}/(start|complete|abandon)$`) },
  { method: "GET", pattern: new RegExp(`^${UUID}/(hints|tutor)$`) },
  { method: "POST", pattern: new RegExp(`^${UUID}/(hints|tutor)$`) },
  { method: "POST", pattern: new RegExp(`^${UUID}/tasks/${TASK}/(answer|solution)$`) },
  { method: "GET", pattern: new RegExp(`^${UUID}/tasks/${TASK}/solution$`) },
];

export function newLearnerToken(): string {
  return randomBytes(24).toString("base64url"); // 32 URL-safe characters
}

function cookieOptions(request: NextRequest) {
  const https =
    request.nextUrl.protocol === "https:" || request.headers.get("x-forwarded-proto") === "https";
  return {
    httpOnly: true,
    sameSite: "lax" as const,
    secure: https,
    path: "/",
    maxAge: 60 * 60 * 24 * 365,
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

export type LearnerProxyConfig = {
  /** The backend path prefix, e.g. "/api/learning". */
  apiPrefix: string;
  /** The only method + path combinations that are forwarded. */
  routes: LearnerRoute[];
  /** The only upstream status codes let through (everything else becomes a generic 503). */
  passThrough: ReadonlySet<number>;
};

/**
 * Forward an allow-listed call to the backend on behalf of the anonymous learner (cookie -> header).
 * Shared by the learning and sandbox proxies, so identity, origin checks and error sanitising are
 * one piece of code.
 */
export async function proxyLearner(
  request: NextRequest,
  config: LearnerProxyConfig,
  segments: string[] | undefined,
  method: "GET" | "POST",
): Promise<NextResponse> {
  const path = (segments ?? []).join("/");
  const allowed = config.routes.some((r) => r.method === method && r.pattern.test(path));
  if (!allowed || (segments ?? []).some((s) => s.length > 60)) return problem(404, "not_found", "Not found.");
  if (method === "POST" && !isSameOrigin(request)) {
    return problem(403, "forbidden", "Cross-site requests are not allowed.");
  }

  const existing = request.cookies.get(LEARNER_COOKIE)?.value;
  const token = existing && /^[A-Za-z0-9_-]{22,64}$/.test(existing) ? existing : newLearnerToken();

  const init: RequestInit = {
    method,
    cache: "no-store",
    headers: {
      Accept: "application/json",
      "X-Learner-Token": token,
      ...(await forwardedFor()),
    },
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  };
  if (method === "POST") {
    const body = await readBody(request);
    if (body === null) return problem(422, "validation_error", "The request body was rejected.");
    init.headers = { ...init.headers, "Content-Type": "application/json" };
    init.body = body;
  }

  let response: NextResponse;
  try {
    response = await forward(
      `${backendUrl()}${config.apiPrefix}${path ? `/${path}` : ""}`,
      init,
      config.passThrough,
    );
  } catch {
    response = problem(503, "unavailable", "The API could not be reached.");
  }
  if (token !== existing) response.cookies.set(LEARNER_COOKIE, token, cookieOptions(request));
  return response;
}

export async function proxyLearning(
  request: NextRequest,
  segments: string[] | undefined,
  method: "GET" | "POST",
): Promise<NextResponse> {
  const path = (segments ?? []).join("/");
  const byCve = /^by-cve\/(.+)$/.exec(path);
  if (byCve && !normalizeCveId(byCve[1]!)) return problem(404, "not_found", "Not found.");
  return proxyLearner(
    request,
    { apiPrefix: "/api/learning", routes: ROUTES, passThrough: LEARNING_PASS_THROUGH },
    segments,
    method,
  );
}

async function forward(
  url: string,
  init: RequestInit,
  passThrough: ReadonlySet<number>,
): Promise<NextResponse> {
  const upstream = await fetch(url, init);
  if (!passThrough.has(upstream.status)) {
    return problem(503, "unavailable", "The API is not available right now.");
  }
  let body: unknown;
  try {
    body = await upstream.json();
  } catch {
    return problem(503, "unavailable", "The API returned an unreadable response.");
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return problem(503, "unavailable", "The API returned an unexpected response.");
  }
  if (upstream.status >= 400) {
    const error = (body as { error?: { code?: unknown; message?: unknown } }).error;
    const code = typeof error?.code === "string" ? error.code.slice(0, 40) : "error";
    const message = typeof error?.message === "string" ? error.message.slice(0, 300) : "Request failed.";
    const retry = upstream.headers.get("retry-after");
    return problem(
      upstream.status,
      code,
      message,
      retry && /^\d{1,6}$/.test(retry) ? { "Retry-After": retry } : {},
    );
  }
  return NextResponse.json(body, { status: upstream.status, headers: NO_STORE });
}
