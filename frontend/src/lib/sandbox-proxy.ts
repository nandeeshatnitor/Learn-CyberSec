import "server-only";

import type { NextRequest, NextResponse } from "next/server";

import { proxyLearner, type LearnerRoute } from "@/lib/learning-proxy";
import { backendUrl, forwardedFor, REQUEST_TIMEOUT_MS } from "@/lib/research-proxy";

/**
 * Same-origin proxies for the lab (sandbox) API.
 *
 *  - `proxySandbox`: the JSON API, for the anonymous learner (cookie -> header), allow-listed.
 *  - `proxyLabApp`: the lab's own web app. The URL itself is the credential (a random token issued
 *    to the learner), because a sandboxed frame cannot send cookies. Responses are passed on with a
 *    fixed set of headers, including the backend's `Content-Security-Policy: sandbox`.
 *
 * The browser never learns the backend URL, a container name or a lab address.
 */
const UUID = "[0-9a-fA-F-]{36}";
const LAB = "[a-z0-9][a-z0-9-]{2,62}";
const SANDBOX_ROUTES: LearnerRoute[] = [
  { method: "GET", pattern: /^labs$/ },
  { method: "GET", pattern: new RegExp(`^labs/${LAB}$`) },
  { method: "POST", pattern: /^instances$/ },
  { method: "GET", pattern: /^instances\/current$/ },
  { method: "GET", pattern: new RegExp(`^instances/${UUID}$`) },
  {
    method: "POST",
    pattern: new RegExp(`^instances/${UUID}/(reset|stop|verify|network-check|terminal-ticket)$`),
  },
  { method: "GET", pattern: new RegExp(`^sessions/${UUID}/labs$`) },
];
const SANDBOX_PASS_THROUGH = new Set([200, 401, 404, 409, 422, 429, 502, 503]);

export function proxySandbox(
  request: NextRequest,
  segments: string[] | undefined,
  method: "GET" | "POST",
): Promise<NextResponse> {
  return proxyLearner(
    request,
    { apiPrefix: "/api/sandbox", routes: SANDBOX_ROUTES, passThrough: SANDBOX_PASS_THROUGH },
    segments,
    method,
  );
}

const MAX_APP_BODY_BYTES = 64_000;
const APP_REQUEST_HEADERS = ["accept", "accept-language", "content-type"];
const APP_RESPONSE_HEADERS = [
  "content-type",
  "content-disposition",
  "content-security-policy",
  "x-content-type-options",
  "cache-control",
  "referrer-policy",
  "cross-origin-resource-policy",
  "location",
];
const NO_BODY = new Set([204, 205, 304]);

function plain(status: number, text: string): Response {
  return new Response(text, {
    status,
    headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" },
  });
}

export async function proxyLabApp(
  request: NextRequest,
  instanceId: string,
  token: string,
  method: "GET" | "HEAD" | "POST",
): Promise<Response> {
  if (!/^[0-9a-f-]{36}$/.test(instanceId) || !/^[A-Za-z0-9_-]{16,64}$/.test(token)) {
    return plain(404, "Not found\n");
  }
  const prefix = `/lab-app/${instanceId}/${token}`;
  // The path exactly as the browser sent it (still percent-encoded): the lab must see the same
  // request, including the dot-dot segments a student is experimenting with.
  const { pathname, search } = request.nextUrl;
  if (!pathname.startsWith(prefix)) return plain(404, "Not found\n");
  const rest = pathname.slice(prefix.length);
  const target = rest === "" ? "/" : rest;
  if (!target.startsWith("/") || target.length > 512) return plain(404, "Not found\n");

  const headers: Record<string, string> = {
    "X-Lab-Prefix": prefix,
    ...(await forwardedFor()),
  };
  for (const name of APP_REQUEST_HEADERS) {
    const value = request.headers.get(name);
    if (value && value.length < 300) headers[name] = value;
  }
  let body: ArrayBuffer | undefined;
  if (method === "POST") {
    body = await request.arrayBuffer();
    if (body.byteLength > MAX_APP_BODY_BYTES) return plain(413, "Request too large\n");
  }

  let upstream: Response;
  try {
    upstream = await fetch(
      `${backendUrl()}/api/sandbox/app/${instanceId}/${token}${target}${search}`,
      {
        method,
        headers,
        body,
        cache: "no-store",
        redirect: "manual",
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      },
    );
  } catch {
    return plain(502, "The lab could not be reached.\n");
  }
  if (upstream.status < 200 || upstream.status > 599) return plain(502, "Bad answer from the lab.\n");
  const out = new Headers({ "Cache-Control": "no-store" });
  for (const name of APP_RESPONSE_HEADERS) {
    const value = upstream.headers.get(name);
    if (value) out.set(name, value);
  }
  const content = method === "HEAD" || NO_BODY.has(upstream.status) ? null : await upstream.arrayBuffer();
  return new Response(content, { status: upstream.status, headers: out });
}

