import "server-only";

import { headers } from "next/headers";

import type { ApiError, ApiResult } from "@/lib/api-types";
import type { CveDetail, CveSearchResponse, HealthResponse, ProviderStatus } from "@/lib/types";

/**
 * Server-side client for the FastAPI backend.
 *
 * `import "server-only"` makes the build fail if this module is ever pulled into a client
 * component, so the backend URL (and anything the backend needs) can never reach the browser.
 * The backend holds all provider credentials; this client neither knows nor sends any.
 */

// Detail lookups fan out to several providers server-side, so allow more than a plain API call.
const REQUEST_TIMEOUT_MS = 30_000;

export type { ApiError, ApiResult } from "@/lib/api-types";

function backendUrl(): string {
  return (process.env.BACKEND_URL ?? "http://localhost:8000").replace(/\/+$/, "");
}

/**
 * The visitor's address, so the backend can rate-limit per visitor instead of treating this
 * server as one client. Only X-Forwarded-For is forwarded (cookies, Authorization and every other
 * header stay here), and only if it looks like a list of IP addresses. The backend believes it only
 * from proxies listed in TRUSTED_PROXIES; put a reverse proxy in front that overwrites this header.
 */
async function forwardedFor(): Promise<Record<string, string>> {
  try {
    const value = (await headers()).get("x-forwarded-for");
    return value && /^[0-9a-fA-F.:,\s]{1,200}$/.test(value) ? { "X-Forwarded-For": value } : {};
  } catch {
    return {}; // not inside a request (for example during a build)
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function providerStatuses(details: unknown): ProviderStatus[] | undefined {
  if (!Array.isArray(details)) return undefined;
  const statuses = details.filter(
    (d): d is ProviderStatus =>
      isRecord(d) && typeof d.provider === "string" && typeof d.status === "string",
  );
  return statuses.length > 0 ? statuses : undefined;
}

async function failure(response: Response): Promise<ApiError> {
  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    // Not JSON: fall through to generic messages.
  }
  const error = isRecord(body) && isRecord(body.error) ? body.error : {};

  if (response.status === 404) return { ok: false, kind: "not_found", message: "Not found." };
  if (response.status === 422) {
    return { ok: false, kind: "invalid", message: "The request was rejected as invalid." };
  }
  if (response.status === 429) {
    const retryAfter = Number(response.headers.get("retry-after"));
    return {
      ok: false,
      kind: "rate_limited",
      message: "Too many requests.",
      retryAfter: Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter : undefined,
    };
  }
  return {
    ok: false,
    kind: "unavailable",
    message: `The API returned HTTP ${response.status}.`,
    providers: providerStatuses(error.details),
  };
}

async function request<T>(path: string, isValid: (data: unknown) => boolean): Promise<ApiResult<T>> {
  let response: Response;
  try {
    response = await fetch(`${backendUrl()}${path}`, {
      cache: "no-store",
      headers: { Accept: "application/json", ...(await forwardedFor()) },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch {
    return { ok: false, kind: "unavailable", message: "The API could not be reached." };
  }

  // /api/health answers 503 with a valid body when the database is down.
  const healthBody = path === "/api/health" && response.status === 503;
  if (!response.ok && !healthBody) return failure(response);

  let data: unknown;
  try {
    data = await response.json();
  } catch {
    return { ok: false, kind: "unavailable", message: "The API returned an unreadable response." };
  }
  if (!isValid(data)) {
    return { ok: false, kind: "unavailable", message: "The API returned an unexpected response." };
  }
  return { ok: true, data: data as T };
}

const hasString = (key: string) => (data: unknown) => isRecord(data) && typeof data[key] === "string";

export function getHealth() {
  return request<HealthResponse>("/api/health", hasString("status"));
}

export function getCve(cveId: string) {
  return request<CveDetail>(`/api/cves/${encodeURIComponent(cveId)}`, hasString("cve_id"));
}

export interface SearchOptions {
  page?: number;
  limit?: number;
  severity?: string;
  knownExploited?: boolean;
}

export function searchCves(query: string, options: SearchOptions = {}) {
  const params = new URLSearchParams({ q: query });
  if (options.page) params.set("page", String(options.page));
  if (options.limit) params.set("limit", String(options.limit));
  if (options.severity) params.set("severity", options.severity);
  if (options.knownExploited) params.set("known_exploited", "true");
  return request<CveSearchResponse>(
    `/api/cves/search?${params}`,
    (data) => isRecord(data) && Array.isArray(data.items) && typeof data.total === "number",
  );
}
